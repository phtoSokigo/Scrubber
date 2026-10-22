<#
.SYNOPSIS
    Set up, start, stop and restart the Scrubber.

.DESCRIPTION
    Setup   Installs WSL and Docker Desktop if they are missing, adds the hosts entry,
            then builds and starts the Scrubber. Asks for administrator rights only when needed.
    Start   Starts Docker Desktop if necessary, then builds and starts the Scrubber.
            Also use Start after you copy in a new version.
    Restart Restarts the Scrubber container.
    Stop    Stops the Scrubber container.
    Status  Shows the container state and checks the web page.
    Logs    Shows the last 200 log lines.
    Open    Opens the Scrubber in the browser.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\scripts\scrubber.ps1 -Action Setup
#>
[CmdletBinding()]
param(
    [ValidateSet('Setup', 'Start', 'Restart', 'Stop', 'Status', 'Logs', 'Open', 'Prereqs')]
    [string]$Action = 'Start',
    [string]$ForUser = '',
    [string]$LogFile = ''
)

# ------------------------------------------------------------------ settings
$HostName  = 'scrubber.test'
$HostIp    = '127.0.0.2'
# ---------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'   # native tools write progress to stderr
$AppDir     = Split-Path -Parent $PSScriptRoot
$Url        = "http://$HostName"
$HostsFile  = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$DockerApp  = Join-Path $env:ProgramFiles 'Docker\Docker\Docker Desktop.exe'
$DockerCli  = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
$DockerUrl  = 'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe'
$script:NeedReboot = $false

function Write-Step([string]$m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Ok([string]$m)   { Write-Host "    OK: $m" -ForegroundColor Green }
function Write-Note([string]$m) { Write-Host "    $m" }
function Write-Warn2([string]$m){ Write-Host "    WARNING: $m" -ForegroundColor Yellow }
function Stop-WithError([string]$m) {
    Write-Host "    ERROR: $m" -ForegroundColor Red
    exit 1
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-DockerCli {
    $cmd = Get-Command docker.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    if (Test-Path $DockerCli) { return $DockerCli }
    return $null
}

function Test-VmPlatform {
    $f = Get-CimInstance Win32_OptionalFeature -Filter "Name='VirtualMachinePlatform'" -ErrorAction SilentlyContinue
    return ($f -and $f.InstallState -eq 1)
}

function Test-WslApp {
    # "wsl --version" works only with the current WSL from the Microsoft Store, which Docker needs.
    foreach ($wsl in (Join-Path $env:SystemRoot 'System32\wsl.exe'), (Join-Path $env:ProgramFiles 'WSL\wsl.exe')) {
        if (-not (Test-Path $wsl)) { continue }
        & $wsl --version *> $null
        if ($LASTEXITCODE -eq 0) { return $true }
    }
    return $false
}

function Install-WslPackage {
    # 1. The built-in installer (current Windows versions).
    $wsl = Join-Path $env:SystemRoot 'System32\wsl.exe'
    if (Test-Path $wsl) {
        & $wsl --install --no-distribution *> $null
        if (Test-WslApp) { return }
        & $wsl --update *> $null
        if (Test-WslApp) { return }
    }
    # 2. winget.
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        Write-Note 'Install WSL with winget.'
        & $winget.Source install --id Microsoft.WSL --exact --silent `
            --accept-package-agreements --accept-source-agreements *> $null
        if (Test-WslApp) { return }
    }
    # 3. The MSI package from the official WSL release page on GitHub.
    Write-Note 'Download WSL from github.com/microsoft/WSL.'
    $arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'x64' }
    $msi = Join-Path $env:TEMP 'wsl-install.msi'
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $ProgressPreference = 'SilentlyContinue'
        $rel = Invoke-RestMethod -Uri 'https://api.github.com/repos/microsoft/WSL/releases/latest' -UseBasicParsing -ErrorAction Stop
        $asset = $rel.assets | Where-Object { $_.name -like "*.$arch.msi" } | Select-Object -First 1
        if (-not $asset) { throw "No $arch MSI in release $($rel.tag_name)." }
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $msi -UseBasicParsing -ErrorAction Stop
    } catch {
        Stop-WithError "Could not download WSL: $($_.Exception.Message)"
    }
    $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart' -Wait -PassThru
    Remove-Item $msi -ErrorAction SilentlyContinue
    if ($p.ExitCode -eq 3010) { $script:NeedReboot = $true }
    elseif ($p.ExitCode -ne 0) { Stop-WithError "The WSL installer failed (exit code $($p.ExitCode))." }
}

function Test-Wsl { return (Test-VmPlatform) -and (Test-WslApp) }

function Test-HostsEntry {
    $pattern = '^\s*' + [regex]::Escape($HostIp) + '\s+' + [regex]::Escape($HostName) + '\s*(#.*)?$'
    $lines = @(Get-Content -Path $HostsFile -ErrorAction SilentlyContinue)
    return [bool]($lines | Where-Object { $_ -match $pattern })
}

# ============================================================ admin part

function Install-Wsl {
    Write-Step 'Check WSL'
    $vmp = Test-VmPlatform
    $app = Test-WslApp
    if ($vmp -and $app) { Write-Ok 'WSL is installed.'; return }

    if (-not $app) {
        Write-Note 'Install WSL. This can take a few minutes.'
        Install-WslPackage
    }
    if (-not (Test-VmPlatform)) {
        foreach ($f in 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform') {
            & dism.exe /online /enable-feature /featurename:$f /all /norestart | Out-Null
            if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 3010) {
                Stop-WithError "Could not turn on the Windows feature $f (exit code $LASTEXITCODE)."
            }
        }
        $script:NeedReboot = $true
    }
    if (-not (Test-WslApp)) {
        if (-not $script:NeedReboot) {
            Stop-WithError 'WSL is still missing after the install. Restart Windows and run Setup.cmd again.'
        }
        Write-Ok 'Windows features are on. Windows must restart before WSL can finish.'
        return
    }
    if ($script:NeedReboot) { Write-Ok 'WSL is installed. Windows must restart.' }
    else { Write-Ok 'WSL is installed.' }
}

function Install-DockerDesktop {
    Write-Step 'Check Docker Desktop'
    if (Test-Path $DockerApp) { Write-Ok 'Docker Desktop is installed.'; return }

    Write-Note 'Install Docker Desktop. This can take 5-10 minutes.'
    $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
    if ($winget) {
        & $winget.Source install --id Docker.DockerDesktop --exact --silent `
            --accept-package-agreements --accept-source-agreements
    }
    if (-not (Test-Path $DockerApp)) {
        Write-Note 'Download the installer from docker.com.'
        $installer = Join-Path $env:TEMP 'DockerDesktopInstaller.exe'
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $ProgressPreference = 'SilentlyContinue'
            Invoke-WebRequest -Uri $DockerUrl -OutFile $installer -UseBasicParsing -ErrorAction Stop
        } catch {
            Stop-WithError "Could not download Docker Desktop: $($_.Exception.Message)"
        }
        $p = Start-Process -FilePath $installer -ArgumentList 'install', '--quiet', '--backend=wsl-2' -Wait -PassThru
        Remove-Item $installer -ErrorAction SilentlyContinue
        if ($p.ExitCode -ne 0) { Stop-WithError "The Docker Desktop installer failed (exit code $($p.ExitCode))." }
    }
    if (-not (Test-Path $DockerApp)) { Stop-WithError 'Docker Desktop is still missing after the install.' }
    Write-Ok 'Docker Desktop is installed. Windows must restart.'
    $script:NeedReboot = $true
}

function Add-DockerUser {
    if (-not $ForUser) { return }
    if (-not (Get-LocalGroup -Name 'docker-users' -ErrorAction SilentlyContinue)) { return }
    try {
        Add-LocalGroupMember -Group 'docker-users' -Member $ForUser -ErrorAction Stop
        Write-Ok "Added $ForUser to the docker-users group."
        $script:NeedReboot = $true
    } catch {
        if ($_.Exception.GetType().Name -ne 'MemberExistsException') {
            Write-Warn2 "Could not add $ForUser to docker-users: $($_.Exception.Message)"
        }
    }
}

function Set-HostsEntry {
    Write-Step "Check the hosts file ($HostIp $HostName)"
    if (Test-HostsEntry) { Write-Ok 'The hosts entry exists.'; return }

    $other = '^\s*\S+\s+' + [regex]::Escape($HostName) + '\s*(#.*)?$'
    $lines = @(Get-Content -Path $HostsFile -ErrorAction Stop | Where-Object { $_ -notmatch $other })
    $lines += "$HostIp`t$HostName`t# Scrubber"
    try {
        Copy-Item $HostsFile "$HostsFile.scrubber.bak" -Force -ErrorAction Stop
        Set-Content -Path $HostsFile -Value $lines -Encoding ASCII -ErrorAction Stop
    } catch {
        Stop-WithError "Could not write the hosts file: $($_.Exception.Message). Antivirus software can block this."
    }
    & ipconfig.exe /flushdns | Out-Null
    Write-Ok "Added $HostIp $HostName. Backup: $HostsFile.scrubber.bak"
}

function Invoke-Prereqs {
    if (-not (Test-Admin)) { Stop-WithError 'Prereqs needs administrator rights.' }
    if ($LogFile) { Start-Transcript -Path $LogFile -Force | Out-Null }

    Write-Step 'Check Windows and virtualization'
    $build = [Environment]::OSVersion.Version.Build
    if ($build -lt 19045) {
        Write-Warn2 "Windows build $build is old. Docker Desktop needs Windows 10 22H2 (19045) or newer. Run Windows Update first."
    } else {
        Write-Ok "Windows build $build."
    }
    $cs  = Get-CimInstance Win32_ComputerSystem
    $cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
    if ($cs.HypervisorPresent -or $cpu.VirtualizationFirmwareEnabled) {
        Write-Ok 'Virtualization is on.'
    } else {
        Write-Warn2 'Virtualization looks off. Turn on VT-x / AMD-V in the BIOS. In a VM, turn on nested virtualization on the host.'
    }

    Install-Wsl
    Install-DockerDesktop
    Add-DockerUser
    Set-HostsEntry

    if ($LogFile) { Stop-Transcript | Out-Null }
    if ($script:NeedReboot) { exit 3010 }
    exit 0
}

# ============================================================ user part

function Start-DockerEngine {
    $docker = Get-DockerCli
    if (-not $docker) { Stop-WithError 'Docker Desktop is not installed. Run Setup.cmd.' }

    & $docker info *> $null
    if ($LASTEXITCODE -eq 0) { Write-Ok 'Docker is running.'; return }

    if (-not (Get-Process -Name 'Docker Desktop' -ErrorAction SilentlyContinue)) {
        Write-Step 'Start Docker Desktop'
        Start-Process -FilePath $DockerApp
    }
    Write-Note 'Wait for Docker. If Docker Desktop shows a terms or sign-in window, complete it.'
    $deadline = (Get-Date).AddMinutes(5)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 3
        & $docker info *> $null
        if ($LASTEXITCODE -eq 0) { Write-Host ''; Write-Ok 'Docker is running.'; return }
        Write-Host '.' -NoNewline
    }
    Write-Host ''
    Stop-WithError 'Docker did not start within 5 minutes. Open Docker Desktop and read the message there.'
}

function Invoke-Compose {
    $docker = Get-DockerCli
    $env:SCRUBBER_IP = $HostIp
    & $docker compose --project-directory $AppDir -f (Join-Path $AppDir 'docker-compose.yml') @args
    if ($LASTEXITCODE -ne 0) { Stop-WithError "docker compose $($args -join ' ') failed (exit code $LASTEXITCODE)." }
}

function Test-Port80 {
    $conns = @(Get-NetTCPConnection -State Listen -LocalPort 80 -ErrorAction SilentlyContinue |
        Where-Object { @('0.0.0.0', '::', $HostIp) -contains $_.LocalAddress })
    foreach ($c in $conns) {
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $name = if ($p) { $p.ProcessName } else { "PID $($c.OwningProcess)" }
        if ($name -match 'docker|wslrelay|vpnkit') { continue }
        Write-Warn2 "$name uses port 80 on $($c.LocalAddress). The Scrubber cannot start while it does."
        if ($c.OwningProcess -eq 4) {
            Write-Note 'PID 4 (System) is usually IIS. Stop it as administrator: Stop-Service W3SVC'
        }
        return $false
    }
    return $true
}

function Wait-App {
    Write-Step "Wait for $Url"
    [Net.WebRequest]::DefaultWebProxy = New-Object Net.WebProxy   # go direct, not through a company proxy
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri "$Url/healthz" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($r.StatusCode -eq 200) { Write-Ok "The Scrubber runs at $Url"; return $true }
        } catch { }
        Start-Sleep -Seconds 2
    }
    try {
        Invoke-WebRequest -Uri "http://$HostIp/healthz" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop | Out-Null
        Write-Warn2 "The Scrubber runs at http://$HostIp, but $HostName does not work. Run Setup.cmd to fix the hosts file."
    } catch {
        Write-Warn2 'The Scrubber does not answer. Run Logs to see why.'
    }
    return $false
}

function Invoke-Start {
    Start-DockerEngine
    if (-not (Test-Port80)) { exit 1 }
    Write-Step 'Build and start the Scrubber'
    Invoke-Compose up -d --build
    if (Wait-App) { Start-Process $Url }
}

function Invoke-Setup {
    Write-Step 'Check what is installed'
    $ready = (Test-Wsl) -and (Test-Path $DockerApp) -and (Test-HostsEntry)
    if ($ready) {
        Write-Ok 'WSL, Docker Desktop and the hosts entry are in place.'
    } else {
        $log = Join-Path $AppDir 'setup.log'
        $user = "$env:USERDOMAIN\$env:USERNAME"
        if (Test-Admin) {
            & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $PSCommandPath -Action Prereqs -ForUser $user
            $code = $LASTEXITCODE
        } else {
            Write-Step 'Ask for administrator rights (installs and hosts file)'
            $argList = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Action Prereqs -ForUser "{1}" -LogFile "{2}"' -f $PSCommandPath, $user, $log
            try {
                $p = Start-Process powershell.exe -Verb RunAs -ArgumentList $argList -Wait -PassThru -ErrorAction Stop
            } catch {
                Stop-WithError 'Administrator rights are necessary for the first setup.'
            }
            $code = $p.ExitCode
            if (Test-Path $log) {
                Get-Content $log | Where-Object { $_ -match '^(==>|    )' } | ForEach-Object { Write-Host $_ }
                Remove-Item $log -ErrorAction SilentlyContinue
            }
        }
        if ($code -eq 3010) {
            Write-Host ''
            Write-Host 'Restart Windows, then run Setup.cmd again.' -ForegroundColor Yellow
            exit 0
        }
        if ($code -ne 0) { Stop-WithError "The setup failed (exit code $code)." }
    }
    Invoke-Start
}

# ============================================================ main

Set-Location $AppDir
switch ($Action) {
    'Setup'   { Invoke-Setup }
    'Prereqs' { Invoke-Prereqs }
    'Start'   { Invoke-Start }
    'Restart' {
        Start-DockerEngine
        Write-Step 'Restart the Scrubber'
        Invoke-Compose restart
        Wait-App | Out-Null
    }
    'Stop' {
        Start-DockerEngine
        Write-Step 'Stop the Scrubber'
        Invoke-Compose stop
        Write-Ok 'The Scrubber is stopped.'
    }
    'Status' {
        Start-DockerEngine
        Invoke-Compose ps
        Wait-App | Out-Null
    }
    'Logs' {
        Start-DockerEngine
        Invoke-Compose logs --tail 200
    }
    'Open' { Start-Process $Url }
}
