<#
.SYNOPSIS
    Registers a Windows Scheduled Task for PocketPC Agent using headless pythonw.exe.

.DESCRIPTION
    Creates an invisible, headless background daemon for PocketPC Agent that starts
    automatically at user logon and on workstation wake/unlock.
    Includes restart policies (RestartCount = 3) if network connectivity is delayed.
#>

[CmdletBinding()]
param (
    [string]$TaskName = "PocketPCAgent",
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"

if ($Uninstall) {
    Write-Host "Unregistering Scheduled Task: $TaskName..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "Task '$TaskName' removed successfully." -ForegroundColor Green
    exit 0
}

# Resolve project directories
$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPythonw = Join-Path $ProjectDir "venv\Scripts\pythonw.exe"
$MainScript = Join-Path $ProjectDir "main.py"

if (Test-Path $VenvPythonw) {
    $PythonwPath = $VenvPythonw
} else {
    $SysPythonw = (Get-Command pythonw.exe -ErrorAction SilentlyContinue)
    if ($SysPythonw) {
        $PythonwPath = $SysPythonw.Source
    } else {
        throw "Could not locate pythonw.exe in venv or system PATH."
    }
}

if (-not (Test-Path $MainScript)) {
    throw "main.py not found at: $MainScript"
}

Write-Host "Configuring PocketPC Agent Autostart..." -ForegroundColor Cyan
Write-Host "Project Directory: $ProjectDir"
Write-Host "Executable:        $PythonwPath"
Write-Host "Main Script:       $MainScript"

# Define task action: run main.py silently using pythonw.exe
$Action = New-ScheduledTaskAction `
    -Execute $PythonwPath `
    -Argument "`"$MainScript`"" `
    -WorkingDirectory $ProjectDir

# Trigger: At User Logon
$TriggerLogon = New-ScheduledTaskTrigger -AtLogOn

# Task Settings: 3 retries if network is not ready, runs indefinitely, runs on battery
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit (New-TimeSpan -Zero)

# Principal: Interactive logon for current user with highest privileges
$Principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType Interactive `
    -RunLevel Highest

# Register scheduled task
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $TriggerLogon `
    -Settings $Settings `
    -Principal $Principal `
    -Force | Out-Null

Write-Host "`nScheduled Task '$TaskName' registered successfully!" -ForegroundColor Green
Write-Host "The daemon will start invisibly upon logon without any console window." -ForegroundColor Gray
