from abc import ABC, abstractmethod
from typing import Any
from uuid import UUID


class BaseMachinery(ABC):
    @abstractmethod
    async def start(
        self,
        sample_data: bytes,
        filename: str,
        config: dict[str, Any] | None = None,
        analysis_id: UUID | str | None = None,
    ) -> dict:
        """Execute a sample and return structured analysis results.

        Args:
            sample_data: Raw bytes of the sample to execute.
            filename: Original filename of the sample.
            config: Optional analysis configuration dict.
            analysis_id: Optional analysis UUID for real-time event streaming.
        """
        ...
