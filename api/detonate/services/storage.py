import io
import time

from minio import Minio
from minio.error import S3Error

from detonate.config import settings


class StorageService:
    def __init__(self) -> None:
        self.client = Minio(
            f"{settings.minio_host}:{settings.minio_port}",
            access_key=settings.minio_root_user,
            secret_key=settings.minio_root_password,
            secure=settings.minio_secure,
        )
        self.bucket = settings.minio_bucket

    def ensure_bucket(self, max_retries: int = 5, delay: float = 2.0) -> None:
        for attempt in range(max_retries):
            try:
                if not self.client.bucket_exists(self.bucket):
                    self.client.make_bucket(self.bucket)
                return
            except Exception:
                if attempt == max_retries - 1:
                    raise
                time.sleep(delay)

    def upload_file(
        self, object_name: str, data: bytes, content_type: str = "application/octet-stream"
    ) -> str:
        self.client.put_object(
            self.bucket,
            object_name,
            io.BytesIO(data),
            length=len(data),
            content_type=content_type,
        )
        return object_name

    def file_exists(self, object_name: str) -> bool:
        try:
            self.client.stat_object(self.bucket, object_name)
            return True
        except S3Error:
            return False

    def get_file(self, object_name: str) -> bytes:
        response = self.client.get_object(self.bucket, object_name)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    def health_check(self) -> bool:
        try:
            self.client.bucket_exists(self.bucket)
            return True
        except Exception:
            return False
