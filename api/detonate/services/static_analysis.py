import logging
import math
import re
import struct
from collections import Counter
from typing import Any

logger = logging.getLogger("detonate.services.static_analysis")


def analyze_entropy(data: bytes) -> dict:
    """Calculate Shannon entropy of file and per-section if PE."""
    if not data:
        return {"overall": 0.0}
    counter = Counter(data)
    length = len(data)
    entropy = -sum(
        (count / length) * math.log2(count / length)
        for count in counter.values()
        if count > 0
    )
    return {"overall": round(entropy, 4)}


def extract_strings(data: bytes, min_length: int = 4) -> dict:
    """Extract ASCII and wide (UTF-16LE) strings from binary data."""
    # ASCII strings
    ascii_strings: list[str] = []
    current: list[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_length:
                ascii_strings.append("".join(current))
            current = []
    if len(current) >= min_length:
        ascii_strings.append("".join(current))

    # Wide strings (UTF-16LE)
    wide_strings: list[str] = []
    i = 0
    current_wide: list[str] = []
    while i < len(data) - 1:
        char = data[i] | (data[i + 1] << 8)
        if 32 <= char < 127:
            current_wide.append(chr(char))
        else:
            if len(current_wide) >= min_length:
                wide_strings.append("".join(current_wide))
            current_wide = []
        i += 2
    if len(current_wide) >= min_length:
        wide_strings.append("".join(current_wide))

    # Categorize interesting strings
    urls = [s for s in ascii_strings if s.startswith(("http://", "https://", "ftp://"))]
    registry_keys = [
        s for s in ascii_strings if s.startswith(("HKEY_", "HKLM\\", "HKCU\\"))
    ]
    file_paths = [
        s for s in ascii_strings if s.startswith(("C:\\", "D:\\", "/etc/", "/tmp/", "/var/"))
    ]

    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    email_re = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")

    ips: list[str] = []
    emails: list[str] = []
    for s in ascii_strings:
        ips.extend(ip_re.findall(s))
        emails.extend(email_re.findall(s))

    # Deduplicate and filter noise
    ips = list(
        set(
            ip
            for ip in ips
            if not ip.startswith("0.") and ip != "127.0.0.1" and ip != "0.0.0.0"
        )
    )
    emails = list(set(emails))

    return {
        "total_ascii": len(ascii_strings),
        "total_wide": len(wide_strings),
        "interesting": {
            "urls": urls[:50],
            "ips": ips[:50],
            "emails": emails[:50],
            "registry_keys": registry_keys[:50],
            "file_paths": file_paths[:50],
        },
        "ascii_strings": ascii_strings[:500],
        "wide_strings": wide_strings[:200],
    }


def analyze_pe(data: bytes) -> dict | None:
    """Parse PE file for imports, exports, sections, resources, certificates."""
    try:
        import pefile
    except ImportError:
        logger.warning("pefile not installed, skipping PE analysis")
        return None

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError:
        return None

    result: dict[str, Any] = {}

    # Basic info
    result["machine"] = hex(pe.FILE_HEADER.Machine)
    result["timestamp"] = pe.FILE_HEADER.TimeDateStamp
    result["characteristics"] = hex(pe.FILE_HEADER.Characteristics)
    result["is_dll"] = bool(pe.FILE_HEADER.Characteristics & 0x2000)
    result["is_exe"] = bool(pe.FILE_HEADER.Characteristics & 0x0002)

    # Optional header
    if hasattr(pe, "OPTIONAL_HEADER"):
        oh = pe.OPTIONAL_HEADER
        result["subsystem"] = oh.Subsystem
        result["entry_point"] = hex(oh.AddressOfEntryPoint)
        result["image_base"] = hex(oh.ImageBase)
        result["linker_version"] = f"{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}"

    # Sections
    sections = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        sect_data = section.get_data()
        sect_entropy = analyze_entropy(sect_data)["overall"] if sect_data else 0
        sections.append(
            {
                "name": name,
                "virtual_address": hex(section.VirtualAddress),
                "virtual_size": section.Misc_VirtualSize,
                "raw_size": section.SizeOfRawData,
                "entropy": sect_entropy,
                "characteristics": hex(section.Characteristics),
            }
        )
    result["sections"] = sections

    # Imports
    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("utf-8", errors="replace"))
                else:
                    funcs.append(f"ordinal_{imp.ordinal}")
            imports[dll_name] = funcs
    result["imports"] = imports
    result["import_count"] = sum(len(v) for v in imports.values())

    # Exports
    exports = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = (
                exp.name.decode("utf-8", errors="replace")
                if exp.name
                else f"ordinal_{exp.ordinal}"
            )
            exports.append(
                {"name": name, "ordinal": exp.ordinal, "address": hex(exp.address)}
            )
    result["exports"] = exports

    # Resources
    resources: list[dict[str, Any]] = []

    def _walk_resources(
        entry: Any, level: int = 0, path: str = ""
    ) -> None:
        if hasattr(entry, "data"):
            resources.append(
                {
                    "type": path,
                    "offset": entry.data.struct.OffsetToData,
                    "size": entry.data.struct.Size,
                    "language": getattr(entry, "id", 0),
                }
            )
        if hasattr(entry, "directory"):
            for child in entry.directory.entries:
                child_name = str(child.name) if child.name else str(child.id)
                _walk_resources(
                    child, level + 1, f"{path}/{child_name}" if path else child_name
                )

    if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        for res_entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            name = str(res_entry.name) if res_entry.name else str(res_entry.id)
            _walk_resources(res_entry, path=name)
    result["resources"] = resources[:100]

    # Digital signatures
    result["has_signature"] = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")

    # Suspicious indicators
    suspicious: list[str] = []
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
        sect_data = section.get_data()
        entropy_val = analyze_entropy(sect_data)["overall"] if sect_data else 0
        if entropy_val > 7.0:
            suspicious.append(f"High entropy section: {name} ({entropy_val:.2f})")
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            suspicious.append(f"Empty raw section with virtual size: {name}")
    if result.get("entry_point") == "0x0":
        suspicious.append("Entry point at 0x0")
    if not result.get("has_signature"):
        suspicious.append("No digital signature")
    if result.get("import_count", 0) < 5:
        suspicious.append(f"Very few imports ({result.get('import_count', 0)})")
    result["suspicious_indicators"] = suspicious

    pe.close()
    return result


def analyze_elf(data: bytes) -> dict | None:
    """Parse ELF file for basic structure."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return None

    result: dict[str, Any] = {}

    # ELF class (32/64 bit)
    ei_class = data[4]
    result["class_"] = "ELF64" if ei_class == 2 else "ELF32"

    # Endianness
    ei_data = data[5]
    little = ei_data == 1
    result["endian"] = "little" if little else "big"
    bo = "<" if little else ">"

    # ELF type
    e_type = struct.unpack(f"{bo}H", data[16:18])[0]
    type_map = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
    result["type"] = type_map.get(e_type, f"UNKNOWN({e_type})")

    # Machine
    e_machine = struct.unpack(f"{bo}H", data[18:20])[0]
    machine_map = {
        3: "x86",
        0x3E: "x86_64",
        0x28: "ARM",
        0xB7: "AArch64",
        8: "MIPS",
    }
    result["machine"] = machine_map.get(e_machine, f"0x{e_machine:x}")

    # Entry point and headers
    if ei_class == 2:  # 64-bit
        entry = struct.unpack(f"{bo}Q", data[24:32])[0]
        ph_num = struct.unpack(f"{bo}H", data[56:58])[0]
        sh_num = struct.unpack(f"{bo}H", data[60:62])[0]
    else:  # 32-bit
        entry = struct.unpack(f"{bo}I", data[24:28])[0]
        ph_num = struct.unpack(f"{bo}H", data[44:46])[0]
        sh_num = struct.unpack(f"{bo}H", data[48:50])[0]

    result["entry_point"] = hex(entry)
    result["program_headers"] = ph_num
    result["section_headers"] = sh_num

    return result


async def run_static_analysis(file_data: bytes, filename: str) -> dict:
    """Run all static analysis on file data. Returns comprehensive results."""
    results: dict[str, Any] = {}

    # Entropy
    results["entropy"] = analyze_entropy(file_data)

    # Strings
    results["strings"] = extract_strings(file_data)

    # PE analysis
    pe_result = analyze_pe(file_data)
    if pe_result:
        results["pe"] = pe_result
        # Add per-section entropy to overall entropy
        section_entropies = {
            s["name"]: s["entropy"] for s in pe_result.get("sections", [])
        }
        results["entropy"]["sections"] = section_entropies

    # ELF analysis
    elf_result = analyze_elf(file_data)
    if elf_result:
        results["elf"] = elf_result

    results["file_size"] = len(file_data)
    results["filename"] = filename

    return results
