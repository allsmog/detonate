"""Machine pool service for managing pre-warmed sandbox containers.

Manages a pool of Docker containers that can be quickly assigned to
analysis tasks. Containers are created ahead of time and tracked in
the database via the Machine model.
"""

import asyncio
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import docker
from docker.errors import DockerException, NotFound
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.config import settings
from detonate.database import async_session_factory
from detonate.machinery.docker import CPU_QUOTA, MEM_LIMIT, SANDBOX_IMAGE
from detonate.models.machine import Machine

logger = logging.getLogger("detonate.services.machine_pool")


class MachinePool:
    """Manages a pool of pre-warmed sandbox containers.

    Each "machine" is a Docker container created from the sandbox image.
    Containers in the pool are created but not started -- they sit idle
    until acquired for an analysis run.

    Thread safety is ensured via an asyncio.Lock on pool mutations.
    Database-level pessimistic locking (SELECT ... FOR UPDATE) prevents
    races when multiple workers attempt to acquire a machine concurrently.
    """

    def __init__(self) -> None:
        self._client: docker.DockerClient | None = None
        self._lock = asyncio.Lock()
        self._platform = settings.sandbox_platform

    @property
    def client(self) -> docker.DockerClient:
        if self._client is None:
            self._client = docker.from_env()
        return self._client

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def initialize(self, pool_size: int | None = None) -> None:
        """Create initial pool of warm containers and sync with DB.

        Cleans up stale DB rows whose containers no longer exist, then
        creates containers until the pool reaches *pool_size*.
        """
        target = pool_size if pool_size is not None else settings.sandbox_pool_size
        logger.info("Initializing machine pool (target=%d, platform=%s)", target, self._platform)

        async with self._lock:
            await self._cleanup_stale_machines()
            current = await self._count_machines()
            needed = max(0, target - current)
            if needed:
                logger.info("Creating %d warm containers", needed)
                for _ in range(needed):
                    await self._create_warm_machine()
            logger.info("Machine pool ready: %d machines", await self._count_machines())

    async def shutdown(self) -> None:
        """Destroy all pool containers and remove DB rows."""
        logger.info("Shutting down machine pool")
        async with self._lock:
            async with async_session_factory() as db:
                result = await db.execute(
                    select(Machine).where(Machine.machinery == "docker")
                )
                machines = list(result.scalars().all())
                for machine in machines:
                    await self._destroy_container(machine.container_id)
                    await db.delete(machine)
                await db.commit()
        logger.info("Machine pool shut down")

    # ------------------------------------------------------------------
    # Acquire / Release
    # ------------------------------------------------------------------

    async def acquire(self, platform: str | None = None) -> Machine:
        """Check out an available machine from the pool.

        Uses SELECT ... FOR UPDATE SKIP LOCKED for safe concurrent access.
        If no machine is available, creates one on-demand.
        """
        platform = platform or self._platform

        async with self._lock:
            async with async_session_factory() as db:
                # Pessimistic lock: skip rows already locked by other transactions
                result = await db.execute(
                    select(Machine)
                    .where(
                        Machine.machinery == "docker",
                        Machine.platform == platform,
                        Machine.status == "available",
                    )
                    .with_for_update(skip_locked=True)
                    .limit(1)
                )
                machine = result.scalar_one_or_none()

                if machine is None:
                    # No available machine -- create one on demand
                    logger.warning("No available machines in pool, creating on-demand")
                    machine = await self._create_warm_machine(db=db)

                machine.status = "busy"
                machine.locked_at = datetime.now(UTC)
                await db.commit()
                await db.refresh(machine)
                logger.info(
                    "Acquired machine %s (container=%s)",
                    machine.name, machine.container_id,
                )
                return machine

    async def release(self, machine: Machine) -> None:
        """Return machine to pool.

        Destroys the used container and creates a fresh replacement
        to keep the pool at its target size.
        """
        async with self._lock:
            async with async_session_factory() as db:
                # Destroy the used container
                old_container_id = machine.container_id
                await self._destroy_container(old_container_id)

                # Refresh machine from DB (it might have been modified)
                result = await db.execute(
                    select(Machine).where(Machine.id == machine.id)
                )
                db_machine = result.scalar_one_or_none()

                if db_machine is None:
                    # Machine was deleted from DB -- just create a replacement
                    logger.warning("Machine %s no longer in DB, creating replacement", machine.name)
                    await self._create_warm_machine(db=db)
                    await db.commit()
                    return

                # Create a fresh container for this machine slot
                new_container = await asyncio.to_thread(self._create_container_sync)
                db_machine.container_id = new_container.id
                db_machine.status = "available"
                db_machine.locked_at = None
                db_machine.last_health_check = datetime.now(UTC)
                await db.commit()

                logger.info(
                    "Released machine %s: destroyed %s, created %s",
                    db_machine.name,
                    old_container_id[:12] if old_container_id else "none",
                    new_container.id[:12],
                )

    # ------------------------------------------------------------------
    # Scaling
    # ------------------------------------------------------------------

    async def scale(self, target_size: int) -> None:
        """Scale pool up or down to target size."""
        async with self._lock:
            current = await self._count_machines(status="available")
            busy = await self._count_machines(status="busy")
            total = current + busy

            if target_size > total:
                # Scale up: add more available machines
                to_add = target_size - total
                logger.info("Scaling up: adding %d machines", to_add)
                for _ in range(to_add):
                    await self._create_warm_machine()
            elif target_size < total:
                # Scale down: remove available machines (never remove busy ones)
                to_remove = min(current, total - target_size)
                if to_remove > 0:
                    logger.info("Scaling down: removing %d available machines", to_remove)
                    async with async_session_factory() as db:
                        result = await db.execute(
                            select(Machine)
                            .where(
                                Machine.machinery == "docker",
                                Machine.status == "available",
                            )
                            .limit(to_remove)
                        )
                        machines = list(result.scalars().all())
                        for m in machines:
                            await self._destroy_container(m.container_id)
                            await db.delete(m)
                        await db.commit()
            else:
                logger.info("Pool already at target size %d", target_size)

    # ------------------------------------------------------------------
    # Health Check
    # ------------------------------------------------------------------

    async def health_check(self) -> dict[str, Any]:
        """Check health of all machines in pool.

        Returns stats and replaces any containers found to be dead.
        """
        async with async_session_factory() as db:
            result = await db.execute(
                select(Machine).where(Machine.machinery == "docker")
            )
            machines = list(result.scalars().all())

        healthy = 0
        unhealthy = 0
        replaced = 0

        for machine in machines:
            is_healthy = await self._check_container_health(machine.container_id)
            if is_healthy:
                healthy += 1
                async with async_session_factory() as db:
                    result = await db.execute(
                        select(Machine).where(Machine.id == machine.id)
                    )
                    db_machine = result.scalar_one_or_none()
                    if db_machine:
                        db_machine.last_health_check = datetime.now(UTC)
                        await db.commit()
            else:
                unhealthy += 1
                # Only replace available (not busy) machines
                if machine.status == "available":
                    logger.warning(
                        "Machine %s container is unhealthy, replacing", machine.name
                    )
                    async with self._lock:
                        await self._replace_machine_container(machine)
                    replaced += 1
                elif machine.status == "busy":
                    logger.warning(
                        "Busy machine %s container is unhealthy -- marking as error",
                        machine.name,
                    )
                    async with async_session_factory() as db:
                        result = await db.execute(
                            select(Machine).where(Machine.id == machine.id)
                        )
                        db_machine = result.scalar_one_or_none()
                        if db_machine:
                            db_machine.status = "error"
                            await db.commit()

        total = await self._count_machines()
        available = await self._count_machines(status="available")
        busy = await self._count_machines(status="busy")
        error = await self._count_machines(status="error")

        return {
            "total": total,
            "available": available,
            "busy": busy,
            "error": error,
            "healthy_checked": healthy,
            "unhealthy_found": unhealthy,
            "replaced": replaced,
        }

    # ------------------------------------------------------------------
    # Status (no lock needed -- read-only)
    # ------------------------------------------------------------------

    async def get_status(self) -> dict[str, Any]:
        """Return pool status summary."""
        total = await self._count_machines()
        available = await self._count_machines(status="available")
        busy = await self._count_machines(status="busy")
        error = await self._count_machines(status="error")

        return {
            "total": total,
            "available": available,
            "busy": busy,
            "error": error,
            "platform": self._platform,
            "pool_enabled": settings.sandbox_pool_enabled,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _create_container_sync(self) -> Any:
        """Create a Docker container (synchronous, run via to_thread)."""
        container = self.client.containers.create(
            SANDBOX_IMAGE,
            command=["sleep", "infinity"],  # Idle -- will be replaced on acquire
            mem_limit=MEM_LIMIT,
            cpu_quota=CPU_QUOTA,
            network_mode="none",
            security_opt=["no-new-privileges"],
            labels={"detonate.pool": "true"},
        )
        return container

    async def _create_warm_machine(self, db: AsyncSession | None = None) -> Machine:
        """Create a container and register it as a Machine in the DB."""
        container = await asyncio.to_thread(self._create_container_sync)

        machine_name = f"pool-{self._platform}-{uuid.uuid4().hex[:8]}"
        machine = Machine(
            name=machine_name,
            machinery="docker",
            platform=self._platform,
            status="available",
            container_id=container.id,
            last_health_check=datetime.now(UTC),
        )

        if db is not None:
            db.add(machine)
            await db.flush()
            await db.refresh(machine)
        else:
            async with async_session_factory() as session:
                session.add(machine)
                await session.commit()
                await session.refresh(machine)

        logger.debug("Created warm machine %s (container=%s)", machine.name, container.id[:12])
        return machine

    async def _destroy_container(self, container_id: str | None) -> None:
        """Force-remove a Docker container."""
        if not container_id:
            return
        try:
            container = await asyncio.to_thread(self.client.containers.get, container_id)
            await asyncio.to_thread(container.remove, force=True)
        except NotFound:
            logger.debug("Container %s already gone", container_id[:12])
        except DockerException as exc:
            logger.warning("Failed to destroy container %s: %s", container_id[:12], exc)

    async def _check_container_health(self, container_id: str | None) -> bool:
        """Check whether a Docker container still exists."""
        if not container_id:
            return False
        try:
            container = await asyncio.to_thread(self.client.containers.get, container_id)
            # Container exists. For 'created' (not-started) containers this is fine.
            return container.status in ("created", "running", "paused")
        except NotFound:
            return False
        except DockerException:
            return False

    async def _replace_machine_container(self, machine: Machine) -> None:
        """Destroy old container and create a new one for an existing Machine row."""
        await self._destroy_container(machine.container_id)
        new_container = await asyncio.to_thread(self._create_container_sync)

        async with async_session_factory() as db:
            result = await db.execute(
                select(Machine).where(Machine.id == machine.id)
            )
            db_machine = result.scalar_one_or_none()
            if db_machine:
                db_machine.container_id = new_container.id
                db_machine.status = "available"
                db_machine.last_health_check = datetime.now(UTC)
                await db.commit()

    async def _cleanup_stale_machines(self) -> None:
        """Remove DB rows whose containers no longer exist."""
        async with async_session_factory() as db:
            result = await db.execute(
                select(Machine).where(Machine.machinery == "docker")
            )
            machines = list(result.scalars().all())
            removed = 0
            for m in machines:
                if not await self._check_container_health(m.container_id):
                    await db.delete(m)
                    removed += 1
            if removed:
                await db.commit()
                logger.info("Cleaned up %d stale machine rows", removed)

    async def _count_machines(self, status: str | None = None) -> int:
        """Count machines in the pool, optionally filtered by status."""
        async with async_session_factory() as db:
            query = select(func.count(Machine.id)).where(Machine.machinery == "docker")
            if status:
                query = query.where(Machine.status == status)
            result = await db.execute(query)
            return result.scalar_one()


# Module-level singleton
_pool: MachinePool | None = None


def get_machine_pool() -> MachinePool:
    """Get or create the singleton MachinePool instance."""
    global _pool
    if _pool is None:
        _pool = MachinePool()
    return _pool
