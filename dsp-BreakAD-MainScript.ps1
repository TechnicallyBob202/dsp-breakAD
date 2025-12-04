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

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "dsp-BreakAD - Security Misconfiguration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

################################################################################
# PREFLIGHT: ENVIRONMENT DISCOVERY
################################################################################

Write-Host "PHASE 1: Environment Discovery" -ForegroundColor Yellow
Write-Host ""

if (-not $SkipPreflight) {
    # Check admin rights
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "ERROR: Administrator privileges required" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [+] Administrator rights verified" -ForegroundColor Green
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Host "ERROR: PowerShell 5.1+ required" -ForegroundColor Red
        exit 1
    }
    Write-Host "  [+] PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
    
    # Import AD module
    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
        Write-Host "  [+] ActiveDirectory module loaded" -ForegroundColor Green
    }
    catch {
        Write-Host "ERROR: Failed to load ActiveDirectory module" -ForegroundColor Red
        exit 1
    }
}

Write-Host ""

# Discover domain and DC info
Write-Host "Discovering domain and domain controllers..." -ForegroundColor Yellow

try {
    $domain = Get-ADDomain -ErrorAction Stop
    $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
    
    if ($dcs -is [array]) {
        $primaryDC = $dcs[0]
    }
    else {
        $primaryDC = $dcs
    }
    
    Write-Host "  [+] Domain: $($domain.Name)" -ForegroundColor Green
    Write-Host "  [+] NetBIOS: $($domain.NetBIOSName)" -ForegroundColor Green
    Write-Host "  [+] Primary DC: $($primaryDC.HostName)" -ForegroundColor Green
}
catch {
    Write-Host "ERROR: Failed to discover domain information: $_" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Preflight checks complete - ready to apply misconfigurations" -ForegroundColor Green
Write-Host ""

################################################################################
# BUILD ENVIRONMENT OBJECT
################################################################################
# This is passed to all modules
# $domain is ADDomain object
# $primaryDC is ADDomainController object

$Environment = @{
    Domain = $domain
    DomainController = $primaryDC
}

# Verify Environment has required properties
if (-not $Environment.Domain.DistinguishedName) {
    Write-Host "ERROR: Environment.Domain missing required properties" -ForegroundColor Red
    exit 1
}

if (-not $Environment.DomainController.HostName) {
    Write-Host "ERROR: Environment.DomainController missing HostName property" -ForegroundColor Red
    exit 1
}

Write-Host "  [+] Environment structure validated" -ForegroundColor Green

################################################################################
# DISCOVER AND LOAD MODULES
################################################################################

Write-Host "PHASE 2: Loading Modules" -ForegroundColor Yellow
Write-Host ""

$modulesPath = Join-Path $Script:ModulesPath "*.psm1"
$moduleFiles = Get-ChildItem -Path $modulesPath -ErrorAction SilentlyContinue | 
    Where-Object { $_.Name -match "dsp-BreakAD-Module-\d+" } | 
    Sort-Object Name

if ($moduleFiles.Count -eq 0) {
    Write-Host "ERROR: No modules found in $Script:ModulesPath" -ForegroundColor Red
    exit 1
}

Write-Host "Found $($moduleFiles.Count) module(s):" -ForegroundColor Cyan

$loadedModules = @()
foreach ($moduleFile in $moduleFiles) {
    try {
        Import-Module $moduleFile.FullName -Force -ErrorAction Stop | Out-Null
        $moduleName = $moduleFile.BaseName
        Write-Host "  [+] $moduleName" -ForegroundColor Green
        $loadedModules += $moduleName
    }
    catch {
        Write-Host "  [X] Failed to load $($moduleFile.BaseName): $_" -ForegroundColor Red
    }
}

Write-Host ""

if ($loadedModules.Count -eq 0) {
    Write-Host "ERROR: No modules loaded successfully" -ForegroundColor Red
    exit 1
}

################################################################################
# EXECUTE MODULES
################################################################################

Write-Host "PHASE 3: Executing Modules" -ForegroundColor Yellow
Write-Host ""

$executedCount = 0
$failedCount = 0

foreach ($moduleName in $loadedModules) {
    # Extract function name from module name
    # dsp-BreakAD-Module-04-AccountSecurity → Invoke-ModuleAccountSecurity
    $functionName = $moduleName -replace "^dsp-BreakAD-Module-\d+-", ""
    $functionName = "Invoke-Module" + $functionName
    
    if (Get-Command -Name $functionName -ErrorAction SilentlyContinue) {
        try {
            Write-Host "Executing $functionName..." -ForegroundColor Cyan
            & $functionName -Environment $Environment
            $executedCount++
        }
        catch {
            Write-Host "ERROR in $functionName : $_" -ForegroundColor Red
            $failedCount++
        }
        Write-Host ""
    }
    else {
        Write-Host "ERROR: Function $functionName not found in $moduleName" -ForegroundColor Red
        $failedCount++
    }
}

################################################################################
# SUMMARY
################################################################################

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Execution Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Executed: $executedCount modules" -ForegroundColor Green
if ($failedCount -gt 0) {
    Write-Host "Failed: $failedCount modules" -ForegroundColor Red
}
Write-Host ""