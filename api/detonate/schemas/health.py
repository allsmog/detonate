from pydantic import BaseModel


class ServiceStatus(BaseModel):
    status: str


class HealthResponse(BaseModel):
    status: str
    db: ServiceStatus
    redis: ServiceStatus
    minio: ServiceStatus
