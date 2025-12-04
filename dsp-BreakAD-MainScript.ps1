################################################################################
##
## dsp-BreakAD-MainScript.ps1
##
## Main orchestration script for dsp-BreakAD security misconfiguration system
##
## Applies intentional security misconfigurations to AD for demonstration:
## - Creates "bad actors" with dangerous permissions
## - Configures delegation abuse
## - Sets weak policies
## - Modifies infrastructure security settings
## - Simulates real-world security issues for DSP to detect and recover
##
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipPreflight
)

$ErrorActionPreference = "Continue"

################################################################################
# INITIALIZATION
################################################################################

$Script:ScriptPath = $PSScriptRoot
$Script:ModulesPath = Join-Path $ScriptPath "modules"
$Script:LogsPath = Join-Path $ScriptPath "logs"

# Create logs directory if it doesn't exist
if (-not (Test-Path $Script:LogsPath)) {
    New-Item -ItemType Directory -Path $Script:LogsPath -Force | Out-Null
}

# Setup logging
$Script:LogFile = Join-Path $Script:LogsPath "dsp-BreakAD-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# Setup logging with transcript
$Script:LogFile = Join-Path $Script:LogsPath "dsp-BreakAD-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'SUCCESS', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to console with color
    switch ($Level) {
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'WARNING' { Write-Host $logMessage -ForegroundColor Yellow }
        'ERROR' { Write-Host $logMessage -ForegroundColor Red }
        default { Write-Host $logMessage }
    }
}

# Start transcript to capture all output
Start-Transcript -Path $Script:LogFile -Append -ErrorAction SilentlyContinue | Out-Null

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "dsp-BreakAD - Security Misconfiguration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "=== dsp-BreakAD Execution Started ===" -Level INFO
Write-Log "Script: $($Script:ScriptPath)" -Level INFO
Write-Log "Log File: $($Script:LogFile)" -Level INFO
Write-Log "" -Level INFO

################################################################################
# PREFLIGHT: ENVIRONMENT DISCOVERY
################################################################################

Write-Log "PHASE 1: Environment Discovery" -Level INFO
Write-Log "" -Level INFO

if (-not $SkipPreflight) {
    # Check admin rights
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "ERROR: Administrator privileges required" -Level ERROR
        exit 1
    }
    Write-Log "Administrator rights verified" -Level SUCCESS
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "ERROR: PowerShell 5.1+ required" -Level ERROR
        exit 1
    }
    Write-Log "PowerShell version: $($PSVersionTable.PSVersion)" -Level SUCCESS
    
    # Import AD module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
        Write-Log "ActiveDirectory module loaded" -Level SUCCESS
    }
    catch {
        Write-Log "ERROR: Failed to load ActiveDirectory module: $_" -Level ERROR
        exit 1
    }
}

Write-Log "" -Level INFO

# Discover domain and DC info
Write-Log "Discovering domain and domain controllers..." -Level INFO

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    
    if ($dcs -is [array]) {
        $primaryDC = $dcs[0]
    }
    else {
        $primaryDC = $dcs
    }
    
    # Use PDCEmulator FQDN - it's the only reliable property
    $dcFQDN = $domain.PDCEmulator
    $primaryDC | Add-Member -MemberType NoteProperty -Name "HostName" -Value $dcFQDN -Force
    
    Write-Log "Domain: $($domain.Name)" -Level SUCCESS
    Write-Log "NetBIOS: $($domain.NetBIOSName)" -Level SUCCESS
    Write-Log "Primary DC: $dcFQDN" -Level SUCCESS
}
catch {
    Write-Log "ERROR: Failed to discover domain information: $_" -Level ERROR
    exit 1
}

Write-Log "" -Level INFO
Write-Log "Preflight checks complete - ready to apply misconfigurations" -Level SUCCESS
Write-Log "" -Level INFO

################################################################################
# BUILD ENVIRONMENT OBJECT
################################################################################
# This is passed to all modules

$Environment = @{
    Domain = $domain
    DomainController = $primaryDC
}

################################################################################
# DISCOVER AND LOAD MODULES
################################################################################

Write-Log "PHASE 2: Loading Modules" -Level INFO
Write-Log "" -Level INFO

# Load logging module first so all other modules can use it
$loggingModule = Join-Path $Script:ScriptPath "dsp-BreakAD-Logging.psm1"
if (Test-Path $loggingModule) {
    try {
        Import-Module $loggingModule -Force -ErrorAction Stop | Out-Null
        Write-Log "Loaded: dsp-BreakAD-Logging" -Level SUCCESS
    }
    catch {
        Write-Log "Failed to load dsp-BreakAD-Logging: $_" -Level ERROR
    }
}

# Make log file available globally
$global:LogFile = $Script:LogFile

$modulesPath = Join-Path $Script:ModulesPath "*.psm1"
$moduleFiles = Get-ChildItem -Path $modulesPath -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match "dsp-BreakAD-Module-\d+" } | 
    Sort-Object Name

if ($moduleFiles.Count -eq 0) {
    Write-Log "ERROR: No modules found in $($Script:ModulesPath)" -Level ERROR
    exit 1
}

Write-Log "Found $($moduleFiles.Count) module(s)" -Level INFO

$loadedModules = @()
foreach ($moduleFile in $moduleFiles) {
    try {
        Import-Module $moduleFile.FullName -Force -ErrorAction Stop | Out-Null
        $moduleName = $moduleFile.BaseName
        Write-Log "Loaded: $moduleName" -Level SUCCESS
        $loadedModules += $moduleName
    }
    catch {
        Write-Log "Failed to load $($moduleFile.BaseName): $_" -Level ERROR
    }
}

Write-Log "" -Level INFO

if ($loadedModules.Count -eq 0) {
    Write-Log "ERROR: No modules loaded successfully" -Level ERROR
    exit 1
}

################################################################################
# EXECUTE MODULES
################################################################################

Write-Log "PHASE 3: Executing Modules" -Level INFO
Write-Log "" -Level INFO

$executedCount = 0
$failedCount = 0

foreach ($moduleName in $loadedModules) {
    # Extract function name from module name
    # dsp-BreakAD-Module-04-AccountSecurity → Invoke-ModuleAccountSecurity
    $functionName = $moduleName -replace "^dsp-BreakAD-Module-\d+-", ""
    $functionName = "Invoke-Module" + $functionName
    
    if (Get-Command -Name $functionName -ErrorAction SilentlyContinue) {
        try {
            Write-Log "Executing $functionName..." -Level INFO
            & $functionName -Environment $Environment
            Write-Log "$functionName completed successfully" -Level SUCCESS
            $executedCount++
        }
        catch {
            Write-Log "ERROR in $functionName : $_" -Level ERROR
            $failedCount++
        }
        Write-Log "" -Level INFO
    }
    else {
        Write-Log "ERROR: Function $functionName not found in $moduleName" -Level ERROR
        $failedCount++
    }
}

################################################################################
# SUMMARY
################################################################################

Write-Log "========================================" -Level INFO
Write-Log "Execution Complete" -Level INFO
Write-Log "========================================" -Level INFO
Write-Log "Executed: $executedCount modules" -Level SUCCESS
if ($failedCount -gt 0) {
    Write-Log "Failed: $failedCount modules" -Level WARNING
}
Write-Log "Log saved to: $($Script:LogFile)" -Level INFO
Write-Log "" -Level INFO

# Stop transcript
Stop-Transcript -ErrorAction SilentlyContinue | Out-Null