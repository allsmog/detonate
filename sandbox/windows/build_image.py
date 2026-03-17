#!/usr/bin/env python3
"""Build and configure a Windows sandbox VM image for Detonate.

This script automates the creation of a Windows qcow2 disk image
suitable for use with the QEMU machinery. It handles:

1. Creating a base qcow2 disk image
2. Launching the VM for initial Windows installation (interactive)
3. Injecting the guest agent and Sysmon config via a CDROM ISO
4. Taking a clean analysis snapshot after setup

Prerequisites (host machine):
  - QEMU/KVM: qemu-system-x86_64, qemu-img
  - genisoimage or mkisofs (for creating the setup ISO)
  - libvirt + virsh (for snapshot management)
  - A Windows 10/11 ISO file
  - Sysmon64.exe from Sysinternals (download separately)
  - Python 3.11+ Windows installer (.msi) for the guest

The process is semi-automated: Windows installation itself is
interactive (requires VNC or SPICE connection), but all pre- and
post-install steps are scripted.

Usage:
  python build_image.py create --iso /path/to/windows.iso
  python build_image.py setup-iso
  python build_image.py snapshot --vm-name detonate-win10
  python build_image.py full --iso /path/to/windows.iso

Full pipeline:
  1. create   - Creates the qcow2 disk and boots the installer
  2. setup-iso - Builds a CDROM ISO with guest agent + Sysmon
  3. (manual) - Install Windows, then run the setup script from CDROM
  4. snapshot - Creates the clean analysis snapshot via libvirt
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_DISK_SIZE = "60G"
DEFAULT_RAM = "4096"
DEFAULT_CPUS = "2"
DEFAULT_VM_NAME = "detonate-win10"
DEFAULT_SNAPSHOT_NAME = "clean"
DEFAULT_DISK_PATH = "detonate-win10.qcow2"
DEFAULT_NETWORK = "default"

SCRIPT_DIR = Path(__file__).parent.resolve()
GUEST_AGENT_PATH = SCRIPT_DIR / "guest_agent.py"
SYSMON_CONFIG_PATH = SCRIPT_DIR / "sysmon_config.xml"

# Virtio driver ISO URL (for disk/network drivers during Windows install)
VIRTIO_DRIVERS_URL = (
    "https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/"
    "stable-virtio/virtio-win.iso"
)


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd: list[str], check: bool = True, **kwargs) -> subprocess.CompletedProcess:
    """Run a command, printing it first for visibility."""
    print(f"  > {' '.join(cmd)}")
    return subprocess.run(cmd, check=check, **kwargs)


def require_tool(name: str) -> str:
    """Check that a CLI tool is available and return its path."""
    path = shutil.which(name)
    if path is None:
        print(f"ERROR: Required tool '{name}' not found in PATH.", file=sys.stderr)
        print(f"       Install it and try again.", file=sys.stderr)
        sys.exit(1)
    return path


def check_kvm_support() -> bool:
    """Check if KVM hardware acceleration is available."""
    if platform.system() != "Linux":
        print("WARNING: KVM is only available on Linux. VM will run without acceleration.")
        return False
    kvm_path = Path("/dev/kvm")
    if not kvm_path.exists():
        print("WARNING: /dev/kvm not found. Is KVM enabled in BIOS?")
        return False
    if not os.access(kvm_path, os.R_OK | os.W_OK):
        print("WARNING: No read/write access to /dev/kvm. Add your user to the 'kvm' group.")
        return False
    return True


# ---------------------------------------------------------------------------
# Step 1: Create base disk image and boot Windows installer
# ---------------------------------------------------------------------------

def cmd_create(args: argparse.Namespace) -> None:
    """Create a qcow2 disk image and launch the Windows installer."""
    require_tool("qemu-img")
    require_tool("qemu-system-x86_64")

    iso_path = Path(args.iso)
    if not iso_path.exists():
        print(f"ERROR: Windows ISO not found: {iso_path}", file=sys.stderr)
        sys.exit(1)

    disk_path = Path(args.disk)
    kvm_available = check_kvm_support()

    # Create the disk image
    if disk_path.exists() and not args.force:
        print(f"Disk image already exists: {disk_path}")
        print("Use --force to overwrite.")
        sys.exit(1)

    print(f"\n[1/3] Creating qcow2 disk image: {disk_path} ({args.disk_size})")
    run_cmd([
        "qemu-img", "create",
        "-f", "qcow2",
        str(disk_path),
        args.disk_size,
    ])

    # Check for virtio drivers ISO
    virtio_iso = Path(args.virtio_iso) if args.virtio_iso else None
    if virtio_iso and not virtio_iso.exists():
        print(f"WARNING: Virtio drivers ISO not found: {virtio_iso}")
        print(f"         Download from: {VIRTIO_DRIVERS_URL}")
        virtio_iso = None

    # Build QEMU command line
    print(f"\n[2/3] Launching QEMU with Windows installer")
    print(f"       Connect via VNC to localhost:5900 to complete installation")
    print(f"       (or use -display sdl for a graphical window)")

    qemu_cmd = [
        "qemu-system-x86_64",
        "-m", args.ram,
        "-smp", args.cpus,
        "-drive", f"file={disk_path},format=qcow2,if=virtio,cache=writeback",
        "-cdrom", str(iso_path),
        "-boot", "d",
        "-vnc", ":0",
        "-usbdevice", "tablet",
        "-net", "nic,model=virtio",
        "-net", "user",
    ]

    if kvm_available:
        qemu_cmd.extend(["-enable-kvm", "-cpu", "host"])
    else:
        qemu_cmd.extend(["-cpu", "max"])

    # Attach virtio driver ISO as a second CDROM if available
    if virtio_iso:
        qemu_cmd.extend(["-drive", f"file={virtio_iso},media=cdrom,index=1"])

    # Use UEFI firmware if available (for Windows 11)
    ovmf_paths = [
        Path("/usr/share/OVMF/OVMF_CODE.fd"),
        Path("/usr/share/edk2/ovmf/OVMF_CODE.fd"),
        Path("/usr/share/qemu/OVMF_CODE.fd"),
    ]
    ovmf_path = None
    for p in ovmf_paths:
        if p.exists():
            ovmf_path = p
            break
    if ovmf_path and args.uefi:
        qemu_cmd.extend(["-bios", str(ovmf_path)])

    print(f"\n[3/3] QEMU started. Complete Windows installation via VNC.")
    print()
    print("  After Windows installation completes:")
    print("  1. Shut down the VM")
    print("  2. Run: python build_image.py setup-iso")
    print("  3. Boot the VM with the setup ISO attached")
    print("  4. Run the setup script from the CDROM drive")
    print("  5. Shut down and run: python build_image.py snapshot")
    print()

    run_cmd(qemu_cmd, check=False)


# ---------------------------------------------------------------------------
# Step 2: Build setup ISO with guest agent and tools
# ---------------------------------------------------------------------------

def cmd_setup_iso(args: argparse.Namespace) -> None:
    """Build an ISO containing the guest agent, Sysmon config, and setup script."""
    # Find ISO creation tool
    mkisofs = shutil.which("genisoimage") or shutil.which("mkisofs")
    if mkisofs is None:
        print("ERROR: genisoimage or mkisofs not found.", file=sys.stderr)
        print("       Install with: apt install genisoimage", file=sys.stderr)
        sys.exit(1)

    iso_dir = Path(args.build_dir) / "setup_iso"
    iso_output = Path(args.output)

    # Clean and create staging directory
    if iso_dir.exists():
        shutil.rmtree(iso_dir)
    iso_dir.mkdir(parents=True)

    print(f"\n[1/4] Staging files for setup ISO")

    # Copy guest agent
    if not GUEST_AGENT_PATH.exists():
        print(f"ERROR: Guest agent not found: {GUEST_AGENT_PATH}", file=sys.stderr)
        sys.exit(1)
    shutil.copy2(GUEST_AGENT_PATH, iso_dir / "guest_agent.py")
    print(f"  Copied: guest_agent.py")

    # Copy Sysmon config
    if not SYSMON_CONFIG_PATH.exists():
        print(f"ERROR: Sysmon config not found: {SYSMON_CONFIG_PATH}", file=sys.stderr)
        sys.exit(1)
    shutil.copy2(SYSMON_CONFIG_PATH, iso_dir / "sysmon_config.xml")
    print(f"  Copied: sysmon_config.xml")

    # Copy Sysmon binary if provided
    sysmon_path = Path(args.sysmon) if args.sysmon else None
    if sysmon_path and sysmon_path.exists():
        shutil.copy2(sysmon_path, iso_dir / sysmon_path.name)
        print(f"  Copied: {sysmon_path.name}")
    else:
        print(f"  NOTE: Sysmon binary not provided. Download Sysmon64.exe from:")
        print(f"         https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon")
        print(f"         Place it in {iso_dir} before burning the ISO, or use --sysmon flag.")

    # Copy Python installer if provided
    python_msi = Path(args.python_msi) if args.python_msi else None
    if python_msi and python_msi.exists():
        shutil.copy2(python_msi, iso_dir / python_msi.name)
        print(f"  Copied: {python_msi.name}")
    else:
        print(f"  NOTE: Python installer not provided. Download from:")
        print(f"         https://www.python.org/downloads/")
        print(f"         Use --python-msi to include it in the ISO.")

    # Generate the setup PowerShell script
    print(f"\n[2/4] Generating setup script")
    setup_script = _generate_setup_script(
        sysmon_exe_name=sysmon_path.name if sysmon_path and sysmon_path.exists() else "Sysmon64.exe",
        python_msi_name=python_msi.name if python_msi and python_msi.exists() else None,
    )
    setup_path = iso_dir / "setup.ps1"
    setup_path.write_text(setup_script, encoding="utf-8")
    print(f"  Generated: setup.ps1")

    # Generate a README for the ISO
    readme = _generate_readme()
    (iso_dir / "README.txt").write_text(readme, encoding="utf-8")
    print(f"  Generated: README.txt")

    # Generate a batch file launcher for convenience
    bat_content = '@echo off\r\npowershell -ExecutionPolicy Bypass -File "%~dp0setup.ps1"\r\npause\r\n'
    (iso_dir / "setup.bat").write_text(bat_content, encoding="utf-8")
    print(f"  Generated: setup.bat")

    # Build the ISO
    print(f"\n[3/4] Building ISO: {iso_output}")
    run_cmd([
        mkisofs,
        "-o", str(iso_output),
        "-V", "DETONATE_SETUP",
        "-J",  # Joliet extensions for Windows compatibility
        "-r",  # Rock Ridge extensions
        str(iso_dir),
    ])

    print(f"\n[4/4] Setup ISO created: {iso_output}")
    print()
    print("  Next steps:")
    print(f"  1. Boot the VM with this ISO attached as a CDROM:")
    print(f"     qemu-system-x86_64 -m 4096 -enable-kvm \\")
    print(f"       -drive file={DEFAULT_DISK_PATH},format=qcow2,if=virtio \\")
    print(f"       -cdrom {iso_output} -vnc :0")
    print(f"  2. Open PowerShell as Administrator in the VM")
    print(f"  3. Run: D:\\setup.bat  (or wherever the CDROM is mounted)")
    print(f"  4. Shut down the VM cleanly")
    print(f"  5. Run: python build_image.py snapshot")


def _generate_setup_script(
    sysmon_exe_name: str = "Sysmon64.exe",
    python_msi_name: str | None = None,
) -> str:
    """Generate the PowerShell setup script for inside the Windows VM.

    This script:
    - Creates required directories
    - Installs Python (if MSI provided)
    - Installs Sysmon with the analysis config
    - Installs the guest agent as a Windows service
    - Configures the firewall
    - Disables Windows Defender and auto-updates
    - Creates the sandbox user account
    """
    python_install_block = ""
    if python_msi_name:
        python_install_block = textwrap.dedent(f"""\
            # Install Python
            Write-Host "[*] Installing Python..." -ForegroundColor Yellow
            $cdrom = (Get-Volume | Where-Object {{ $_.FileSystemLabel -eq 'DETONATE_SETUP' }}).DriveLetter
            $pythonMsi = "${{cdrom}}:\\{python_msi_name}"
            if (Test-Path $pythonMsi) {{
                Start-Process msiexec.exe -ArgumentList "/i `"$pythonMsi`" /quiet /norestart InstallAllUsers=1 PrependPath=1 Include_pip=1" -Wait -NoNewWindow
                Write-Host "[+] Python installed" -ForegroundColor Green
            }} else {{
                Write-Host "[!] Python installer not found on CDROM: $pythonMsi" -ForegroundColor Red
                Write-Host "    Download Python 3.11+ from https://python.org and install manually." -ForegroundColor Red
            }}
        """)
    else:
        python_install_block = textwrap.dedent("""\
            # Python must be installed manually
            Write-Host "[!] Python not included in setup ISO." -ForegroundColor Red
            Write-Host "    Install Python 3.11+ manually before creating the snapshot." -ForegroundColor Red
            Write-Host "    Download from: https://python.org" -ForegroundColor Red
        """)

    return textwrap.dedent(f"""\
        #Requires -RunAsAdministrator
        <#
        .SYNOPSIS
            Detonate sandbox setup script for Windows VM.
        .DESCRIPTION
            Configures a clean Windows installation for malware analysis:
            - Installs Python and Sysmon
            - Deploys the guest agent as a Windows service
            - Configures firewall and disables security features
            - Creates a sandbox user account
        .NOTES
            Run this script from an elevated PowerShell prompt.
            The CDROM drive with setup files must be mounted.
        #>

        $ErrorActionPreference = "Stop"
        Set-StrictMode -Version Latest

        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Detonate Windows Sandbox Setup" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""

        # Find the CDROM drive letter
        $cdrom = (Get-Volume | Where-Object {{ $_.FileSystemLabel -eq 'DETONATE_SETUP' }}).DriveLetter
        if (-not $cdrom) {{
            # Fallback: try all CDROM drives
            $cdrom = (Get-WmiObject Win32_CDROMDrive | Select-Object -First 1).Drive.TrimEnd(':')
        }}
        if (-not $cdrom) {{
            Write-Host "[!] Could not find CDROM drive. Mount the setup ISO and try again." -ForegroundColor Red
            exit 1
        }}
        Write-Host "[*] Found setup CDROM at drive ${{cdrom}}:" -ForegroundColor Yellow

        # ---------------------------------------------------------------
        # 1. Create directories
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Creating directories..." -ForegroundColor Yellow

        $dirs = @(
            "C:\\Users\\sandbox",
            "C:\\Users\\sandbox\\samples",
            "C:\\Users\\sandbox\\results",
            "C:\\Users\\sandbox\\Desktop",
            "C:\\Users\\sandbox\\Documents",
            "C:\\Tools",
            "C:\\Tools\\Sysmon",
            "C:\\Tools\\GuestAgent"
        )
        foreach ($dir in $dirs) {{
            if (-not (Test-Path $dir)) {{
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
            }}
        }}
        Write-Host "[+] Directories created" -ForegroundColor Green

        # ---------------------------------------------------------------
        # 2. Install Python
        # ---------------------------------------------------------------
        Write-Host ""
        {python_install_block}

        # ---------------------------------------------------------------
        # 3. Install Sysmon
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Installing Sysmon..." -ForegroundColor Yellow

        $sysmonSrc = "${{cdrom}}:\\{sysmon_exe_name}"
        $sysmonDst = "C:\\Tools\\Sysmon\\{sysmon_exe_name}"
        $sysmonConfig = "${{cdrom}}:\\sysmon_config.xml"

        if (Test-Path $sysmonSrc) {{
            Copy-Item $sysmonSrc $sysmonDst -Force
            Copy-Item $sysmonConfig "C:\\Tools\\Sysmon\\sysmon_config.xml" -Force

            # Install Sysmon as a service with our config
            & $sysmonDst -accepteula -i "C:\\Tools\\Sysmon\\sysmon_config.xml" 2>&1 | Out-Null
            Write-Host "[+] Sysmon installed and configured" -ForegroundColor Green
        }} else {{
            Write-Host "[!] Sysmon binary not found on CDROM: $sysmonSrc" -ForegroundColor Red
            Write-Host "    Download Sysmon64.exe from:" -ForegroundColor Red
            Write-Host "    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon" -ForegroundColor Red
        }}

        # ---------------------------------------------------------------
        # 4. Install Guest Agent
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Installing guest agent..." -ForegroundColor Yellow

        $agentSrc = "${{cdrom}}:\\guest_agent.py"
        $agentDst = "C:\\Tools\\GuestAgent\\guest_agent.py"
        Copy-Item $agentSrc $agentDst -Force

        # Find Python executable
        $pythonExe = $null
        $pythonPaths = @(
            "C:\\Python311\\python.exe",
            "C:\\Python312\\python.exe",
            "C:\\Python313\\python.exe",
            "C:\\Program Files\\Python311\\python.exe",
            "C:\\Program Files\\Python312\\python.exe",
            "C:\\Program Files\\Python313\\python.exe",
            (Get-Command python -ErrorAction SilentlyContinue).Source
        )
        foreach ($p in $pythonPaths) {{
            if ($p -and (Test-Path $p)) {{
                $pythonExe = $p
                break
            }}
        }}

        if ($pythonExe) {{
            Write-Host "[*] Found Python at: $pythonExe" -ForegroundColor Yellow

            # Create a Windows service using sc.exe
            # The service runs the guest agent on boot
            $serviceName = "DetonateAgent"
            $serviceDisplay = "Detonate Guest Agent"
            $serviceBin = "`"$pythonExe`" `"$agentDst`""

            # Remove existing service if present
            sc.exe stop $serviceName 2>&1 | Out-Null
            sc.exe delete $serviceName 2>&1 | Out-Null

            # Create the service wrapper batch file (sc.exe can't run Python directly)
            $wrapperPath = "C:\\Tools\\GuestAgent\\run_agent.bat"
            @"
@echo off
"$pythonExe" "C:\\Tools\\GuestAgent\\guest_agent.py"
"@ | Set-Content -Path $wrapperPath -Encoding ASCII

            # Use NSSM if available, otherwise create a scheduled task
            $nssm = Get-Command nssm -ErrorAction SilentlyContinue
            if ($nssm) {{
                & nssm install $serviceName $pythonExe $agentDst
                & nssm set $serviceName AppDirectory "C:\\Tools\\GuestAgent"
                & nssm set $serviceName Start SERVICE_AUTO_START
                & nssm set $serviceName DisplayName $serviceDisplay
                & nssm start $serviceName
                Write-Host "[+] Guest agent installed as Windows service (NSSM)" -ForegroundColor Green
            }} else {{
                # Fallback: create a scheduled task that runs at startup
                $action = New-ScheduledTaskAction -Execute $pythonExe -Argument "`"$agentDst`""
                $trigger = New-ScheduledTaskTrigger -AtStartup
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero)

                Register-ScheduledTask -TaskName $serviceName -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings -Force | Out-Null
                Start-ScheduledTask -TaskName $serviceName
                Write-Host "[+] Guest agent installed as scheduled task (runs at startup)" -ForegroundColor Green
            }}
        }} else {{
            Write-Host "[!] Python not found. Install Python first, then re-run setup." -ForegroundColor Red
        }}

        # ---------------------------------------------------------------
        # 5. Configure Firewall
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Configuring firewall..." -ForegroundColor Yellow

        # Allow inbound connections to guest agent port
        New-NetFirewallRule -DisplayName "Detonate Guest Agent" `
            -Direction Inbound -Protocol TCP -LocalPort 8080 `
            -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null

        # Allow outbound connections (for malware to make network calls)
        # This is usually already allowed by default, but ensure it
        Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultOutboundAction Allow -ErrorAction SilentlyContinue

        Write-Host "[+] Firewall configured (port 8080 open)" -ForegroundColor Green

        # ---------------------------------------------------------------
        # 6. Disable Windows Defender
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Disabling Windows Defender..." -ForegroundColor Yellow

        # Disable real-time protection via PowerShell
        try {{
            Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
            Set-MpPreference -DisableBehaviorMonitoring $true -ErrorAction Stop
            Set-MpPreference -DisableBlockAtFirstSeen $true -ErrorAction Stop
            Set-MpPreference -DisableIOAVProtection $true -ErrorAction Stop
            Set-MpPreference -DisablePrivacyMode $true -ErrorAction Stop
            Set-MpPreference -MAPSReporting 0 -ErrorAction Stop
            Set-MpPreference -SubmitSamplesConsent 2 -ErrorAction Stop
            Write-Host "[+] Windows Defender real-time protection disabled" -ForegroundColor Green
        }} catch {{
            Write-Host "[!] Could not disable Defender via PowerShell: $($_.Exception.Message)" -ForegroundColor Red
            Write-Host "    Try disabling via Group Policy (gpedit.msc) or Tamper Protection in Settings." -ForegroundColor Red
        }}

        # Disable via registry (may require Tamper Protection off first)
        try {{
            $defenderPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
            if (-not (Test-Path $defenderPath)) {{
                New-Item -Path $defenderPath -Force | Out-Null
            }}
            Set-ItemProperty -Path $defenderPath -Name "DisableAntiSpyware" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $defenderPath -Name "DisableAntiVirus" -Value 1 -Type DWord -Force

            $rtPath = "$defenderPath\\Real-Time Protection"
            if (-not (Test-Path $rtPath)) {{
                New-Item -Path $rtPath -Force | Out-Null
            }}
            Set-ItemProperty -Path $rtPath -Name "DisableRealtimeMonitoring" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $rtPath -Name "DisableBehaviorMonitoring" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $rtPath -Name "DisableOnAccessProtection" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $rtPath -Name "DisableScanOnRealtimeEnable" -Value 1 -Type DWord -Force
            Write-Host "[+] Defender registry policies set" -ForegroundColor Green
        }} catch {{
            Write-Host "[!] Could not set Defender registry policies: $($_.Exception.Message)" -ForegroundColor Red
        }}

        # ---------------------------------------------------------------
        # 7. Disable Windows Update
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Disabling Windows Update..." -ForegroundColor Yellow

        try {{
            # Stop and disable Windows Update service
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Set-Service -Name wuauserv -StartupType Disabled -ErrorAction Stop

            # Disable via registry
            $wuPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU"
            if (-not (Test-Path $wuPath)) {{
                New-Item -Path $wuPath -Force | Out-Null
            }}
            Set-ItemProperty -Path $wuPath -Name "NoAutoUpdate" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $wuPath -Name "AUOptions" -Value 1 -Type DWord -Force

            Write-Host "[+] Windows Update disabled" -ForegroundColor Green
        }} catch {{
            Write-Host "[!] Could not fully disable Windows Update: $($_.Exception.Message)" -ForegroundColor Red
        }}

        # ---------------------------------------------------------------
        # 8. Disable miscellaneous noise sources
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Disabling system noise sources..." -ForegroundColor Yellow

        try {{
            # Disable screen saver
            Set-ItemProperty -Path "HKCU:\\Control Panel\\Desktop" -Name "ScreenSaveActive" -Value "0" -Force

            # Disable sleep/hibernate
            powercfg -change -standby-timeout-ac 0
            powercfg -change -hibernate-timeout-ac 0
            powercfg -change -monitor-timeout-ac 0

            # Disable UAC prompts (for smoother malware execution)
            $uacPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
            Set-ItemProperty -Path $uacPath -Name "EnableLUA" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $uacPath -Name "ConsentPromptBehaviorAdmin" -Value 0 -Type DWord -Force

            # Disable Windows Error Reporting
            $werPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\Windows Error Reporting"
            Set-ItemProperty -Path $werPath -Name "Disabled" -Value 1 -Type DWord -Force -ErrorAction SilentlyContinue

            # Disable automatic maintenance
            $maintPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance"
            if (-not (Test-Path $maintPath)) {{
                New-Item -Path $maintPath -Force | Out-Null
            }}
            Set-ItemProperty -Path $maintPath -Name "MaintenanceDisabled" -Value 1 -Type DWord -Force

            Write-Host "[+] System noise sources disabled" -ForegroundColor Green
        }} catch {{
            Write-Host "[!] Some noise sources could not be disabled: $($_.Exception.Message)" -ForegroundColor Red
        }}

        # ---------------------------------------------------------------
        # 9. Create sandbox user
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "[*] Creating sandbox user account..." -ForegroundColor Yellow

        try {{
            $userExists = Get-LocalUser -Name "sandbox" -ErrorAction SilentlyContinue
            if (-not $userExists) {{
                $password = ConvertTo-SecureString "sandbox" -AsPlainText -Force
                New-LocalUser -Name "sandbox" -Password $password -FullName "Sandbox User" -Description "Detonate sandbox analysis user" -PasswordNeverExpires | Out-Null
                Add-LocalGroupMember -Group "Administrators" -Member "sandbox" -ErrorAction SilentlyContinue
            }}
            Write-Host "[+] Sandbox user created (username: sandbox, password: sandbox)" -ForegroundColor Green
        }} catch {{
            Write-Host "[!] Could not create sandbox user: $($_.Exception.Message)" -ForegroundColor Red
        }}

        # ---------------------------------------------------------------
        # Done
        # ---------------------------------------------------------------
        Write-Host ""
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host "  Setup complete!" -ForegroundColor Cyan
        Write-Host "============================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Verify the guest agent is running:" -ForegroundColor White
        Write-Host "     curl http://localhost:8080/health" -ForegroundColor Gray
        Write-Host "  2. Reboot to apply all changes" -ForegroundColor White
        Write-Host "  3. After reboot, verify agent starts automatically" -ForegroundColor White
        Write-Host "  4. Shut down the VM cleanly" -ForegroundColor White
        Write-Host "  5. On the host, create the snapshot:" -ForegroundColor White
        Write-Host "     python build_image.py snapshot --vm-name {DEFAULT_VM_NAME}" -ForegroundColor Gray
        Write-Host ""
    """)


def _generate_readme() -> str:
    """Generate README.txt for the setup ISO."""
    return textwrap.dedent("""\
        Detonate Windows Sandbox Setup
        ==============================

        This CDROM contains the files needed to configure a Windows VM
        for use as a Detonate malware analysis sandbox.

        Files:
          setup.bat          - Run this (as Administrator) to set up everything
          setup.ps1          - PowerShell setup script (called by setup.bat)
          guest_agent.py     - Python HTTP server for sandbox communication
          sysmon_config.xml  - Sysmon configuration for malware analysis
          README.txt         - This file

        Quick Start:
          1. Open PowerShell as Administrator
          2. Run: D:\\setup.bat  (adjust drive letter if needed)
          3. Follow the on-screen instructions
          4. Reboot, verify agent works, then shut down for snapshot

        Requirements:
          - Windows 10 or 11
          - Python 3.11+ (installer may be included on this disc)
          - Sysmon64.exe (may be included on this disc)

        For more information, see the Detonate project documentation.
    """)


# ---------------------------------------------------------------------------
# Step 3: Create clean analysis snapshot
# ---------------------------------------------------------------------------

def cmd_snapshot(args: argparse.Namespace) -> None:
    """Create a clean snapshot of the VM using virsh."""
    require_tool("virsh")

    vm_name = args.vm_name
    snapshot_name = args.snapshot_name

    print(f"\n[1/3] Checking VM state: {vm_name}")

    # Verify VM exists
    result = subprocess.run(
        ["virsh", "dominfo", vm_name],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: VM '{vm_name}' not found in libvirt.", file=sys.stderr)
        print(f"       Create it first or check the name.", file=sys.stderr)
        sys.exit(1)

    # Check if VM is shut off (required for offline snapshot)
    state_line = [l for l in result.stdout.splitlines() if "State:" in l]
    if state_line:
        state = state_line[0].split(":", 1)[1].strip()
        print(f"  VM state: {state}")
        if state != "shut off":
            print(f"  WARNING: VM is not shut off. Creating a running snapshot.")
            print(f"           For best results, shut down the VM first.")

    # Delete existing snapshot with same name (if any)
    print(f"\n[2/3] Checking for existing snapshot: {snapshot_name}")
    existing = subprocess.run(
        ["virsh", "snapshot-info", vm_name, snapshot_name],
        capture_output=True, text=True,
    )
    if existing.returncode == 0:
        if args.force:
            print(f"  Deleting existing snapshot: {snapshot_name}")
            run_cmd(["virsh", "snapshot-delete", vm_name, snapshot_name])
        else:
            print(f"  Snapshot '{snapshot_name}' already exists. Use --force to replace.", file=sys.stderr)
            sys.exit(1)

    # Create the snapshot
    print(f"\n[3/3] Creating snapshot: {snapshot_name}")
    run_cmd([
        "virsh", "snapshot-create-as",
        vm_name,
        "--name", snapshot_name,
        "--description", "Detonate clean analysis snapshot",
    ])

    print(f"\nSnapshot created successfully!")
    print(f"  VM:       {vm_name}")
    print(f"  Snapshot: {snapshot_name}")
    print()
    print(f"You can now use this VM with the QEMU machinery:")
    print(f"  QEMU_BASE_IMAGE={vm_name}")
    print(f"  QEMU_SNAPSHOT_NAME={snapshot_name}")


# ---------------------------------------------------------------------------
# Full pipeline
# ---------------------------------------------------------------------------

def cmd_full(args: argparse.Namespace) -> None:
    """Run the full image creation pipeline."""
    print("=" * 60)
    print("  Detonate Windows VM Image Builder - Full Pipeline")
    print("=" * 60)
    print()
    print("This will guide you through creating a Windows analysis VM.")
    print()
    print("Phase 1: Create disk image and install Windows")
    print("  This launches QEMU with the Windows ISO.")
    print("  Connect via VNC to localhost:5900 to install Windows.")
    print()

    cmd_create(args)

    print()
    print("-" * 60)
    print()
    print("After Windows installation is complete and the VM has shut down,")
    print("run the next steps manually:")
    print()
    print(f"  python {__file__} setup-iso")
    print(f"  # Boot VM with setup ISO, run setup.bat inside VM")
    print(f"  python {__file__} snapshot --vm-name {args.vm_name}")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a Windows sandbox VM image for Detonate.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              # Create disk and launch Windows installer
              python build_image.py create --iso windows10.iso

              # Build setup ISO with all tools
              python build_image.py setup-iso --sysmon Sysmon64.exe --python-msi python-3.12.0-amd64.msi

              # Create clean snapshot after setup
              python build_image.py snapshot --vm-name detonate-win10

              # Full guided pipeline
              python build_image.py full --iso windows10.iso
        """),
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # -- create --
    create_p = subparsers.add_parser("create", help="Create disk image and boot installer")
    create_p.add_argument("--iso", required=True, help="Path to Windows ISO file")
    create_p.add_argument("--disk", default=DEFAULT_DISK_PATH, help=f"Output qcow2 path (default: {DEFAULT_DISK_PATH})")
    create_p.add_argument("--disk-size", default=DEFAULT_DISK_SIZE, help=f"Disk size (default: {DEFAULT_DISK_SIZE})")
    create_p.add_argument("--ram", default=DEFAULT_RAM, help=f"RAM in MB (default: {DEFAULT_RAM})")
    create_p.add_argument("--cpus", default=DEFAULT_CPUS, help=f"CPU count (default: {DEFAULT_CPUS})")
    create_p.add_argument("--virtio-iso", help="Path to virtio-win.iso for drivers")
    create_p.add_argument("--uefi", action="store_true", help="Use UEFI firmware (for Windows 11)")
    create_p.add_argument("--force", action="store_true", help="Overwrite existing disk image")

    # -- setup-iso --
    setup_p = subparsers.add_parser("setup-iso", help="Build setup CDROM ISO")
    setup_p.add_argument("--output", default="detonate-setup.iso", help="Output ISO path")
    setup_p.add_argument("--build-dir", default="/tmp/detonate-build", help="Temporary build directory")
    setup_p.add_argument("--sysmon", help="Path to Sysmon64.exe binary")
    setup_p.add_argument("--python-msi", help="Path to Python .msi installer")

    # -- snapshot --
    snap_p = subparsers.add_parser("snapshot", help="Create clean analysis snapshot")
    snap_p.add_argument("--vm-name", default=DEFAULT_VM_NAME, help=f"Libvirt domain name (default: {DEFAULT_VM_NAME})")
    snap_p.add_argument("--snapshot-name", default=DEFAULT_SNAPSHOT_NAME, help=f"Snapshot name (default: {DEFAULT_SNAPSHOT_NAME})")
    snap_p.add_argument("--force", action="store_true", help="Replace existing snapshot")

    # -- full --
    full_p = subparsers.add_parser("full", help="Full guided pipeline")
    full_p.add_argument("--iso", required=True, help="Path to Windows ISO file")
    full_p.add_argument("--disk", default=DEFAULT_DISK_PATH, help=f"Output qcow2 path")
    full_p.add_argument("--disk-size", default=DEFAULT_DISK_SIZE, help=f"Disk size")
    full_p.add_argument("--ram", default=DEFAULT_RAM, help=f"RAM in MB")
    full_p.add_argument("--cpus", default=DEFAULT_CPUS, help=f"CPU count")
    full_p.add_argument("--virtio-iso", help="Path to virtio-win.iso")
    full_p.add_argument("--uefi", action="store_true", help="Use UEFI firmware")
    full_p.add_argument("--force", action="store_true", help="Overwrite existing files")
    full_p.add_argument("--vm-name", default=DEFAULT_VM_NAME, help=f"Libvirt domain name")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        sys.exit(1)

    commands = {
        "create": cmd_create,
        "setup-iso": cmd_setup_iso,
        "snapshot": cmd_snapshot,
        "full": cmd_full,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
