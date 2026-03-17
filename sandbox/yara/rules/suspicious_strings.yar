rule Suspicious_Base64_Commands
{
    meta:
        description = "Detects base64 encoded command patterns"
        severity = "medium"
        author = "Detonate"

    strings:
        $b64_bin_sh = "L2Jpbi9zaA" // /bin/sh
        $b64_bin_bash = "L2Jpbi9iYXNo" // /bin/bash
        $b64_etc_passwd = "L2V0Yy9wYXNzd2Q" // /etc/passwd
        $b64_etc_shadow = "L2V0Yy9zaGFkb3c" // /etc/shadow

    condition:
        any of them
}

rule Suspicious_PowerShell_Patterns
{
    meta:
        description = "Detects PowerShell download cradles and obfuscation"
        severity = "high"
        author = "Detonate"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "IEX(" nocase
        $ps4 = "Invoke-WebRequest" nocase
        $ps5 = "DownloadString" nocase
        $ps6 = "DownloadFile" nocase
        $ps7 = "Net.WebClient" nocase
        $ps8 = "-EncodedCommand" nocase
        $ps9 = "-enc " nocase
        $ps10 = "FromBase64String" nocase

    condition:
        2 of them
}

rule Suspicious_Shell_Commands
{
    meta:
        description = "Detects suspicious shell command patterns"
        severity = "medium"
        author = "Detonate"

    strings:
        $wget_pipe = /wget\s+.{5,80}\|\s*(sh|bash)/
        $curl_pipe = /curl\s+.{5,80}\|\s*(sh|bash)/
        $chmod_exec = /chmod\s+(\+x|[0-7]*7[0-7]*)\s/
        $rm_rf = "rm -rf /" ascii
        $dev_null = ">/dev/null 2>&1"
        $nohup = "nohup " ascii
        $disown = "disown" ascii

    condition:
        any of them
}

rule Suspicious_Credential_Access
{
    meta:
        description = "Detects references to credential files and paths"
        severity = "high"
        author = "Detonate"

    strings:
        $passwd = "/etc/passwd" ascii
        $shadow = "/etc/shadow" ascii
        $ssh_dir = ".ssh/id_rsa" ascii
        $ssh_auth = ".ssh/authorized_keys" ascii
        $bash_history = ".bash_history" ascii
        $aws_creds = ".aws/credentials" ascii
        $docker_config = ".docker/config.json" ascii
        $kube_config = ".kube/config" ascii
        $gnupg = ".gnupg/" ascii

    condition:
        2 of them
}

rule Suspicious_Anti_Analysis
{
    meta:
        description = "Detects anti-analysis and sandbox detection strings"
        severity = "medium"
        author = "Detonate"

    strings:
        $vbox1 = "VirtualBox" ascii nocase
        $vbox2 = "VBOX" ascii
        $vmware1 = "VMware" ascii nocase
        $vmware2 = "vmtoolsd" ascii
        $qemu = "QEMU" ascii
        $sandbox1 = "sandbox" ascii nocase
        $sandbox2 = "malware" ascii nocase
        $debug1 = "strace" ascii
        $debug2 = "ltrace" ascii
        $debug3 = "gdb" ascii
        $proc_status = "/proc/self/status" ascii

    condition:
        3 of them
}

rule Suspicious_C2_Patterns
{
    meta:
        description = "Detects common command and control communication patterns"
        severity = "high"
        author = "Detonate"

    strings:
        $beacon = "beacon" ascii nocase
        $callback = "callback" ascii nocase
        $c2_server = "c2_server" ascii nocase
        $heartbeat = "heartbeat" ascii nocase
        $user_agent_fake = "Mozilla/5.0" ascii
        $exfil = "exfiltrat" ascii nocase

    condition:
        2 of them
}

rule Contains_IP_Address
{
    meta:
        description = "File contains IP address literals"
        severity = "low"
        author = "Detonate"

    strings:
        $ip = /\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b/

    condition:
        #ip > 2
}

rule Contains_URL_Patterns
{
    meta:
        description = "File contains URL patterns suggesting network activity"
        severity = "low"
        author = "Detonate"

    strings:
        $http = "http://" ascii
        $https = "https://" ascii
        $ftp = "ftp://" ascii

    condition:
        any of them
}

rule Suspicious_Encoding_Decoding
{
    meta:
        description = "Detects encoding and decoding function usage"
        severity = "medium"
        author = "Detonate"

    strings:
        $base64_dec = "base64" ascii nocase
        $hex_decode = "hex_decode" ascii nocase
        $xor_key = "xor_key" ascii nocase
        $rot13 = "rot13" ascii nocase
        $atob = "atob(" ascii
        $btoa = "btoa(" ascii

    condition:
        2 of them
}

rule Suspicious_Python_Patterns
{
    meta:
        description = "Detects suspicious Python code patterns"
        severity = "medium"
        author = "Detonate"

    strings:
        $exec = "exec(" ascii
        $eval = "eval(" ascii
        $compile = "compile(" ascii
        $import_os = "import os" ascii
        $import_subprocess = "import subprocess" ascii
        $import_socket = "import socket" ascii
        $import_ctypes = "import ctypes" ascii
        $marshal = "marshal.loads" ascii

    condition:
        ($exec or $eval or $compile) and 2 of ($import_*)
}
