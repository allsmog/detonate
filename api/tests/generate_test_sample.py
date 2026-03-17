#!/usr/bin/env python3
"""Generate a safe test PE binary with embedded artifacts for E2E AI testing.

Creates a minimal valid PE32 executable with:
- Valid MZ/PE headers that pefile can parse
- Suspicious strings (API calls, commands, registry keys)
- Fake network IOCs (URLs, IPs, domains using .test TLD)
- Benign strings for realistic noise

Output: api/tests/fixtures/test_sample.bin
"""

import struct
from pathlib import Path

# Strings embedded in the .text section — each gives the agent tools something to find
EMBEDDED_STRINGS = [
    # Benign / typical PE strings
    b"Microsoft Visual C++ Runtime Library",
    b"kernel32.dll",
    b"ntdll.dll",
    b"user32.dll",
    b"GetProcAddress",
    b"LoadLibraryA",
    b"ExitProcess",
    # Suspicious API calls (process injection indicators)
    b"CreateRemoteThread",
    b"VirtualAllocEx",
    b"WriteProcessMemory",
    b"NtUnmapViewOfSection",
    # Suspicious commands
    b"cmd.exe /c whoami",
    b"powershell -enc JABjAGwAaQBlAG4AdAA=",
    # Registry persistence
    b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    # Network IOCs (fake, using .test TLD per RFC 2606)
    b"http://malware-c2.evil.test/beacon",
    b"http://dropper.evil.test/stage2.bin",
    b"192.168.100.50",
    b"10.13.37.100",
    b"dropper.evil.test",
    b"exfil.evil.test",
    # Identity string
    b"Detonate E2E Test Sample - NOT MALWARE",
]


def align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def build_pe() -> bytes:
    FILE_ALIGNMENT = 0x200
    SECTION_ALIGNMENT = 0x1000
    PE_OFFSET = 0x80

    # Build section data first to know sizes
    section_data = b"\x00".join(EMBEDDED_STRINGS) + b"\x00"
    section_virtual_size = len(section_data)
    section_raw_size = align(section_virtual_size, FILE_ALIGNMENT)
    image_size = SECTION_ALIGNMENT + align(section_virtual_size, SECTION_ALIGNMENT)

    pe = bytearray()

    # === DOS Header (64 bytes) ===
    dos = bytearray(64)
    struct.pack_into("<H", dos, 0, 0x5A4D)       # e_magic = "MZ"
    struct.pack_into("<I", dos, 0x3C, PE_OFFSET)  # e_lfanew
    pe += dos

    # === DOS Stub (fills 0x40 to PE_OFFSET) ===
    stub = b"This program cannot be run in DOS mode.\r\n$"
    pe += stub + b"\x00" * (PE_OFFSET - 64 - len(stub))

    # === PE Signature ===
    pe += b"PE\x00\x00"

    # === COFF File Header (20 bytes) ===
    pe += struct.pack(
        "<HHIIIHH",
        0x014C,      # Machine: IMAGE_FILE_MACHINE_I386
        1,           # NumberOfSections
        0x65A3B400,  # TimeDateStamp
        0,           # PointerToSymbolTable
        0,           # NumberOfSymbols
        224,         # SizeOfOptionalHeader (PE32)
        0x0102,      # Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE
    )

    # === Optional Header PE32 (224 bytes) ===
    opt = bytearray()

    # Standard fields (28 bytes)
    opt += struct.pack("<H", 0x010B)                # Magic (PE32)
    opt += struct.pack("<BB", 14, 0)                # Linker version
    opt += struct.pack("<I", section_raw_size)       # SizeOfCode
    opt += struct.pack("<I", 0)                      # SizeOfInitializedData
    opt += struct.pack("<I", 0)                      # SizeOfUninitializedData
    opt += struct.pack("<I", 0x1000)                 # AddressOfEntryPoint
    opt += struct.pack("<I", 0x1000)                 # BaseOfCode
    opt += struct.pack("<I", 0x1000)                 # BaseOfData (PE32 only)
    assert len(opt) == 28

    # Windows-specific fields (68 bytes)
    opt += struct.pack("<I", 0x00400000)             # ImageBase
    opt += struct.pack("<I", SECTION_ALIGNMENT)      # SectionAlignment
    opt += struct.pack("<I", FILE_ALIGNMENT)          # FileAlignment
    opt += struct.pack("<HH", 6, 0)                  # OS version
    opt += struct.pack("<HH", 0, 0)                  # Image version
    opt += struct.pack("<HH", 6, 0)                  # Subsystem version
    opt += struct.pack("<I", 0)                      # Win32VersionValue
    opt += struct.pack("<I", image_size)             # SizeOfImage
    opt += struct.pack("<I", FILE_ALIGNMENT)          # SizeOfHeaders
    opt += struct.pack("<I", 0)                      # CheckSum
    opt += struct.pack("<HH", 3, 0)                  # Subsystem (CUI), DllCharacteristics
    opt += struct.pack("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)  # Stack/Heap sizes
    opt += struct.pack("<I", 0)                      # LoaderFlags
    opt += struct.pack("<I", 16)                     # NumberOfRvaAndSizes
    assert len(opt) == 96

    # Data directories (16 entries * 8 bytes = 128 bytes, all zeroed)
    opt += b"\x00" * 128
    assert len(opt) == 224

    pe += opt

    # === Section Header: .text (40 bytes) ===
    pe += struct.pack(
        "<8sIIIIIIHHI",
        b".text",             # Name (padded to 8 bytes by struct)
        section_virtual_size,  # VirtualSize
        0x1000,               # VirtualAddress
        section_raw_size,      # SizeOfRawData
        FILE_ALIGNMENT,        # PointerToRawData
        0,                    # PointerToRelocations
        0,                    # PointerToLinenumbers
        0,                    # NumberOfRelocations
        0,                    # NumberOfLinenumbers
        0x60000020,           # CNT_CODE | MEM_EXECUTE | MEM_READ
    )

    # Pad headers to FileAlignment
    pe += b"\x00" * (FILE_ALIGNMENT - len(pe))

    # === Section data ===
    pe += section_data
    pe += b"\x00" * (section_raw_size - len(section_data))

    return bytes(pe)


if __name__ == "__main__":
    data = build_pe()

    out_dir = Path(__file__).parent / "fixtures"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "test_sample.bin"
    out_path.write_bytes(data)

    print(f"Generated {out_path} ({len(data)} bytes)")

    # Quick validation
    try:
        import pefile

        pe = pefile.PE(data=data, fast_load=True)
        print(f"  pefile: machine={hex(pe.FILE_HEADER.Machine)} "
              f"sections={pe.FILE_HEADER.NumberOfSections} "
              f"entry={hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        pe.close()
        print("  pefile: OK")
    except ImportError:
        print("  pefile not installed, skipping validation")
    except Exception as e:
        print(f"  pefile: FAILED - {e}")
