rule UPX_Packed
{
    meta:
        description = "Detects UPX packed executables"
        severity = "medium"
        author = "Detonate"

    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX2" ascii
        $upx_sig = { 55 50 58 21 }

    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_Packed_Generic
{
    meta:
        description = "Detects potentially packed ELF binaries by entropy indicators"
        severity = "medium"
        author = "Detonate"

    strings:
        $elf_magic = { 7F 45 4C 46 }
        $no_section = ".packed" ascii
        $stub = "PROT_EXEC" ascii

    condition:
        $elf_magic at 0 and ($no_section or $stub)
}

rule Obfuscated_Shell_Script
{
    meta:
        description = "Detects obfuscated shell scripts"
        severity = "medium"
        author = "Detonate"

    strings:
        $shebang = "#!/bin/" ascii
        $eval_echo = /eval\s+.*echo/ ascii
        $eval_base64 = /eval\s+.*base64/ ascii
        $hex_escape = /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/ ascii
        $dollar_brace = /\$\{[!#@*]/ ascii
        $rev_pipe = "| rev" ascii

    condition:
        $shebang and 2 of ($eval_*, $hex_escape, $dollar_brace, $rev_pipe)
}

rule Python_Bytecode_Exec
{
    meta:
        description = "Detects compiled Python bytecode that may be used for evasion"
        severity = "low"
        author = "Detonate"

    strings:
        $pyc_magic_311 = { A7 0D 0D 0A }
        $pyc_magic_310 = { 6F 0D 0D 0A }
        $pyc_magic_312 = { CB 0D 0D 0A }
        $marshal = "marshal" ascii

    condition:
        ($pyc_magic_311 at 0 or $pyc_magic_310 at 0 or $pyc_magic_312 at 0) or
        ($marshal and filesize < 100KB)
}

rule XOR_Encoded_Content
{
    meta:
        description = "Detects XOR encoding patterns common in obfuscation"
        severity = "medium"
        author = "Detonate"

    strings:
        $xor_loop_c = { 30 ?? 4? E2 }
        $xor_str = "xor" ascii nocase
        $cipher = "cipher" ascii nocase
        $decrypt = "decrypt" ascii nocase
        $encode = "encode" ascii nocase

    condition:
        $xor_loop_c or (2 of ($xor_str, $cipher, $decrypt, $encode) and filesize < 500KB)
}

rule Packed_Binary_Indicators
{
    meta:
        description = "Detects indicators of packed or compressed binary content"
        severity = "low"
        author = "Detonate"

    strings:
        $elf_magic = { 7F 45 4C 46 }
        $zlib = { 78 9C }
        $gzip = { 1F 8B 08 }
        $bzip2 = { 42 5A 68 }
        $lzma = { 5D 00 00 }

    condition:
        $elf_magic at 0 and any of ($zlib, $gzip, $bzip2, $lzma)
}
