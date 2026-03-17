from pydantic import BaseModel, ConfigDict, Field


class EntropyResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    overall: float = 0.0
    sections: dict[str, float] | None = None


class InterestingStrings(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    urls: list[str] = Field(default_factory=list)
    ips: list[str] = Field(default_factory=list)
    emails: list[str] = Field(default_factory=list)
    registry_keys: list[str] = Field(default_factory=list)
    file_paths: list[str] = Field(default_factory=list)


class StringsResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    total_ascii: int = 0
    total_wide: int = 0
    interesting: InterestingStrings = Field(default_factory=InterestingStrings)
    ascii_strings: list[str] = Field(default_factory=list)
    wide_strings: list[str] = Field(default_factory=list)


class PESectionInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    virtual_address: str
    virtual_size: int
    raw_size: int
    entropy: float
    characteristics: str


class PEImportInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    dll: str
    functions: list[str] = Field(default_factory=list)


class PEExportInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    ordinal: int
    address: str


class PEResourceInfo(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    offset: int
    size: int
    language: int = 0


class PEAnalysisResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    machine: str
    timestamp: int = 0
    characteristics: str | None = None
    is_dll: bool = False
    is_exe: bool = False
    subsystem: int | None = None
    entry_point: str | None = None
    image_base: str | None = None
    linker_version: str | None = None
    sections: list[PESectionInfo] = Field(default_factory=list)
    imports: dict[str, list[str]] = Field(default_factory=dict)
    import_count: int = 0
    exports: list[PEExportInfo] = Field(default_factory=list)
    resources: list[PEResourceInfo] = Field(default_factory=list)
    has_signature: bool = False
    suspicious_indicators: list[str] = Field(default_factory=list)


class ELFAnalysisResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    class_: str = Field(alias="class_")
    type: str
    machine: str
    endian: str
    entry_point: str
    program_headers: int = 0
    section_headers: int = 0


class StaticAnalysisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    entropy: EntropyResult
    strings: StringsResult
    pe: PEAnalysisResult | None = None
    elf: ELFAnalysisResult | None = None
    file_size: int = 0
    filename: str = ""


class StringsSearchResponse(BaseModel):
    """Paginated response for the dedicated strings endpoint."""

    model_config = ConfigDict(from_attributes=True)

    total_ascii: int = 0
    total_wide: int = 0
    interesting: InterestingStrings = Field(default_factory=InterestingStrings)
    ascii_strings: list[str] = Field(default_factory=list)
    wide_strings: list[str] = Field(default_factory=list)
    page: int = 1
    page_size: int = 100
    total_results: int = 0
