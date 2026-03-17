import os

broker_url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
result_backend = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")

task_serializer = "json"
result_serializer = "json"
accept_content = ["json"]
timezone = "UTC"
enable_utc = True

task_routes = {
    "worker.tasks.static.*": {"queue": "static"},
    "worker.tasks.dynamic.*": {"queue": "dynamic"},
    "worker.tasks.ai.*": {"queue": "ai"},
    "worker.tasks.threat_intel.*": {"queue": "enrichment"},
}

task_default_queue = "static"
