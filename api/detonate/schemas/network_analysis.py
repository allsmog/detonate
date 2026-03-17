"""Pydantic schemas for the advanced network analysis endpoints."""


from pydantic import BaseModel, Field


class EnrichedConnection(BaseModel):
    """A single network connection enriched with service metadata."""

    protocol: str = "tcp"
    address: str = ""
    port: int = 0
    service: str = ""
    is_private: bool = False
    direction: str = "outbound"


class ConnectionSummary(BaseModel):
    """Aggregate statistics about observed network connections."""

    total: int = 0
    external: int = 0
    internal: int = 0
    services: list[str] = Field(default_factory=list)
    unique_ips: list[str] = Field(default_factory=list)


class DNSAnalysis(BaseModel):
    """Breakdown of DNS activity observed during analysis."""

    total_queries: int = 0
    unique_domains: list[str] = Field(default_factory=list)
    query_types: dict[str, int] = Field(default_factory=dict)


class PcapStats(BaseModel):
    """Raw PCAP file statistics."""

    total_packets: int = 0
    total_bytes: int = 0
    pcap_size: int = 0


class NetworkAnalysisResponse(BaseModel):
    """Full enriched network analysis returned by GET .../network."""

    connections: list[EnrichedConnection] = Field(default_factory=list)
    connection_summary: ConnectionSummary = Field(default_factory=ConnectionSummary)
    dns_analysis: DNSAnalysis = Field(default_factory=DNSAnalysis)
    http_hosts: list[str] = Field(default_factory=list)
    pcap_stats: PcapStats = Field(default_factory=PcapStats)
    suspicious_indicators: list[str] = Field(default_factory=list)


class NetworkIOCsResponse(BaseModel):
    """Extracted network Indicators of Compromise."""

    ips: list[str] = Field(default_factory=list)
    private_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    total: int = 0
