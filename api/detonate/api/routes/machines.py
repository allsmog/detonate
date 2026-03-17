from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from detonate.api.deps import get_db
from detonate.config import settings
from detonate.models.machine import Machine
from detonate.schemas.machine import (
    MachineListResponse,
    MachineResponse,
    PoolScaleRequest,
    PoolStatusResponse,
)
from detonate.services.machine_pool import get_machine_pool

router = APIRouter()


@router.get("/machines", response_model=MachineListResponse)
async def list_machines(
    db: AsyncSession = Depends(get_db),
) -> MachineListResponse:
    """List all machines in the pool with their status."""
    result = await db.execute(
        select(Machine).order_by(Machine.name)
    )
    machines = list(result.scalars().all())
    return MachineListResponse(
        items=[MachineResponse.model_validate(m) for m in machines],
        total=len(machines),
    )


@router.get("/machines/pool/status", response_model=PoolStatusResponse)
async def pool_status() -> PoolStatusResponse:
    """Get machine pool health and stats."""
    pool = get_machine_pool()
    status = await pool.get_status()
    return PoolStatusResponse(**status)


@router.post("/machines/pool/scale", response_model=PoolStatusResponse)
async def scale_pool(body: PoolScaleRequest) -> PoolStatusResponse:
    """Scale the machine pool to a target size."""
    if not settings.sandbox_pool_enabled:
        raise HTTPException(
            status_code=409,
            detail="Machine pool is not enabled. Set SANDBOX_POOL_ENABLED=true.",
        )

    pool = get_machine_pool()
    await pool.scale(body.size)
    status = await pool.get_status()
    return PoolStatusResponse(**status)


@router.post("/machines/pool/health-check")
async def run_health_check() -> dict:
    """Run a health check on all pool machines.

    Detects dead containers and replaces them.
    """
    if not settings.sandbox_pool_enabled:
        raise HTTPException(
            status_code=409,
            detail="Machine pool is not enabled. Set SANDBOX_POOL_ENABLED=true.",
        )

    pool = get_machine_pool()
    result = await pool.health_check()
    return result


@router.get("/machines/{machine_id}", response_model=MachineResponse)
async def get_machine(
    machine_id: UUID,
    db: AsyncSession = Depends(get_db),
) -> MachineResponse:
    """Get details for a specific machine."""
    result = await db.execute(
        select(Machine).where(Machine.id == machine_id)
    )
    machine = result.scalar_one_or_none()
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    return MachineResponse.model_validate(machine)
