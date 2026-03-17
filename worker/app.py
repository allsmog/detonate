import os

from celery import Celery

_broker = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")

celery_app = Celery("detonate", broker=_broker, backend=_broker)
celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "worker.tasks.static.*": {"queue": "static"},
        "worker.tasks.dynamic.*": {"queue": "dynamic"},
        "worker.tasks.ai.*": {"queue": "ai"},
        "worker.tasks.threat_intel.*": {"queue": "enrichment"},
    },
    task_default_queue="static",
    imports=[
        "worker.tasks.dynamic",
        "worker.tasks.ai",
        "worker.tasks.threat_intel",
    ],
)

# Keep backward compat alias
app = celery_app
