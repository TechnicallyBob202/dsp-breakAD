################################################################################
##
## dsp-breakAD.ps1
##
## Main orchestration script for dsp-breakAD
## Applies intentional AD misconfigurations for DSP demonstration
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('InfrastructureSecurity', 'AccountSecurity', 'ADDelegation', 'KerberosSecurity', 'GroupPolicySecurity')]
    [string[]]$ModuleNames,
    
    [Parameter(Mandatory=$false)]
    [switch]$All,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPreflight
)

$ErrorActionPreference = "Continue"

################################################################################
# INITIALIZATION
################################################################################

$Script:ScriptPath = $PSScriptRoot
$Script:ModulesPath = Join-Path $ScriptPath "modules"
$Script:ConfigPath = Join-Path $ScriptPath "dsp-breakAD.config"
$Script:LogsPath = Join-Path $ScriptPath "logs"

# Import logging module first
$loggingModule = Join-Path $ScriptPath "dsp-BreakAD-Logging.psm1"
if (Test-Path $loggingModule) {
    Import-Module $loggingModule -Force -ErrorAction Stop | Out-Null
}
else {
    Write-Host "ERROR: Logging module not found at $loggingModule" -ForegroundColor Red
    exit 1
}

# Initialize logging
$logFile = Initialize-Logging -LogsDirectory $Script:LogsPath

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "dsp-breakAD - Security Misconfiguration" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "=== dsp-breakAD Execution Started ===" -Level INFO
Write-Log "Script Path: $Script:ScriptPath" -Level INFO
Write-Log "Log File: $logFile" -Level INFO
Write-Log "" -Level INFO

################################################################################
# PREFLIGHT CHECKS
################################################################################

Write-LogSection "PHASE 1: Preflight Checks"

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
        Write-Log "ERROR: PowerShell 5.1+ required. Current: $($PSVersionTable.PSVersion)" -Level ERROR
        exit 1
    }
    Write-Log "PowerShell version: $($PSVersionTable.PSVersion)" -Level SUCCESS
    
    # Check/import AD module
    Write-Log "Checking ActiveDirectory module..." -Level INFO
    try {
        Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
        Write-Log "ActiveDirectory module loaded" -Level SUCCESS
    }
    catch {
        Write-Log "ERROR: Failed to load ActiveDirectory module: $_" -Level ERROR
        exit 1
    }
    
    # Discover domain info
    Write-Log "Discovering domain and domain controller info..." -Level INFO
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        if ($dcs -is [array]) {
            $primaryDC = $dcs | Where-Object { $_.OperatingSystem -like "*2019*" -or $_.OperatingSystem -like "*2022*" } | Select-Object -First 1
            if (-not $primaryDC) {
                $primaryDC = $dcs[0]
            }
        }
        else {
            $primaryDC = $dcs
        }
        
        Write-Log "Domain: $($domain.Name)" -Level SUCCESS
        Write-Log "Domain DN: $($domain.DistinguishedName)" -Level SUCCESS
        Write-Log "Forest: $($domain.Forest)" -Level SUCCESS
        Write-Log "Primary DC: $($primaryDC.HostName)" -Level SUCCESS
    }
    catch {
        Write-Log "ERROR: Failed to discover domain information: $_" -Level ERROR
        exit 1
    }
    
    # Validate can't-break conditions
    Write-Log "Validating can't-break conditions..." -Level INFO
    try {
        # Check replication health
        $replHealth = Get-ADReplicationFailure -EnumerationServer $primaryDC.HostName -ErrorAction SilentlyContinue
        if ($replHealth) {
            Write-Log "WARNING: Replication issues detected - proceed with caution" -Level WARNING
        }
        else {
            Write-Log "Replication health verified" -Level SUCCESS
        }
        
        # Check DC connectivity
        $dcTest = Test-NetConnection -ComputerName $primaryDC.HostName -CommonTCPPort LDAP -WarningAction SilentlyContinue
        if (-not $dcTest.TcpTestSucceeded) {
            Write-Log "ERROR: Cannot connect to DC on LDAP port" -Level ERROR
            exit 1
        }
        Write-Log "DC connectivity verified" -Level SUCCESS
    }
    catch {
        Write-Log "WARNING: Could not fully validate can't-break conditions: $_" -Level WARNING
    }
    
    Write-Log "" -Level INFO
    Write-Log "Preflight checks complete - ready to apply misconfigurations" -Level SUCCESS
}

Write-Log "" -Level INFO

################################################################################
# LOAD CONFIGURATION
################################################################################

Write-LogSection "PHASE 2: Load Configuration"

$config = @{}
if (Test-Path $Script:ConfigPath) {
    Write-Log "Loading configuration from: $Script:ConfigPath" -Level INFO
    $configContent = Get-Content $Script:ConfigPath -Raw
    $config = ConvertFrom-StringData $configContent
    Write-Log "Configuration loaded successfully" -Level SUCCESS
}
else {
    Write-Log "WARNING: Config file not found, using defaults" -Level WARNING
}

Write-Log "" -Level INFO

################################################################################
# MODULE SELECTION
################################################################################

Write-LogSection "PHASE 3: Module Selection"

$availableModules = @(
    "InfrastructureSecurity",
    "AccountSecurity",
    "ADDelegation",
    "KerberosSecurity",
    "GroupPolicySecurity"
)

$selectedModules = @()

if ($All) {
    $selectedModules = $availableModules
    Write-Log "All modules selected via -All parameter" -Level INFO
}
elseif ($ModuleNames) {
    $selectedModules = $ModuleNames
    Write-Log "Modules selected via parameter: $($ModuleNames -join ', ')" -Level INFO
}
else {
    # Interactive prompt
    Write-Host ""
    Write-Host "Available modules:" -ForegroundColor Cyan
    Write-Host "  1) InfrastructureSecurity - Print spooler, schema admins, dSHeuristics" -ForegroundColor White
    Write-Host "  2) AccountSecurity - Bad user accounts, weak policies" -ForegroundColor White
    Write-Host "  3) ADDelegation - Unconstrained/constrained delegation abuse" -ForegroundColor White
    Write-Host "  4) KerberosSecurity - Weak encryption, pre-auth bypass" -ForegroundColor White
    Write-Host "  5) GroupPolicySecurity - Weaken GPO permissions and settings" -ForegroundColor White
    Write-Host "  6) All - Run all modules" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Select modules (comma-separated numbers, or 'all')"
    
    if ($choice -eq "all") {
        $selectedModules = $availableModules
    }
    else {
        $choices = $choice -split "," | ForEach-Object { $_.Trim() }
        $moduleMap = @{
            "1" = "InfrastructureSecurity"
            "2" = "AccountSecurity"
            "3" = "ADDelegation"
            "4" = "KerberosSecurity"
            "5" = "GroupPolicySecurity"
        }
        
        foreach ($c in $choices) {
            if ($moduleMap.ContainsKey($c)) {
                $selectedModules += $moduleMap[$c]
            }
        }
    }
    
    Write-Log "Modules selected via interactive prompt: $($selectedModules -join ', ')" -Level INFO
}

if ($selectedModules.Count -eq 0) {
    Write-Log "ERROR: No modules selected" -Level ERROR
    exit 1
}

Write-Log "Selected $($selectedModules.Count) module(s)" -Level SUCCESS
Write-Log "" -Level INFO

################################################################################
# LOAD MODULES
################################################################################

Write-LogSection "PHASE 4: Load Modules"

$loadedModules = @()
$modulesToLoad = Get-ChildItem -Path $Script:ModulesPath -Filter "dsp-BreakAD-Module-*.psm1" -ErrorAction SilentlyContinue | Sort-Object Name

if ($modulesToLoad.Count -eq 0) {
    Write-Log "WARNING: No module files found in $Script:ModulesPath" -Level WARNING
}

foreach ($moduleFile in $modulesToLoad) {
    $moduleName = $moduleFile.BaseName -replace "dsp-BreakAD-Module-\d+-", ""
    
    if ($moduleName -in $selectedModules) {
        try {
            Import-Module $moduleFile.FullName -Force -ErrorAction Stop | Out-Null
            Write-Log "Loaded: $moduleName" -Level SUCCESS
            $loadedModules += $moduleName
        }
        catch {
            Write-Log "ERROR: Failed to load $moduleName : $_" -Level ERROR
        }
    }
}

Write-Log "" -Level INFO

if ($loadedModules.Count -eq 0) {
    Write-Log "ERROR: No modules loaded successfully" -Level ERROR
    Close-Logging
    exit 1
}

Write-Log "Successfully loaded $($loadedModules.Count) module(s)" -Level SUCCESS
Write-Log "" -Level INFO

################################################################################
# BUILD ENVIRONMENT OBJECT
################################################################################

$Environment = @{
    Domain = $domain
    DomainController = $primaryDC
    Config = $config
}

################################################################################
# EXECUTE MODULES
################################################################################

Write-LogSection "PHASE 5: Execute Modules"

$executedCount = 0
$failedCount = 0

foreach ($moduleName in $loadedModules) {
    Write-LogSection "Executing: $moduleName"
    
    # Build function name
    $functionName = "Invoke-Module$moduleName"
    
    if (Get-Command -Name $functionName -ErrorAction SilentlyContinue) {
        try {
            Write-Log "Starting $functionName..." -Level INFO
            $result = & $functionName -Environment $Environment
            
            if ($result -eq $false) {
                Write-Log "WARNING: $functionName completed with errors" -Level WARNING
                $failedCount++
            }
            else {
                Write-Log "$functionName completed successfully" -Level SUCCESS
                $executedCount++
            }
        }
        catch {
            Write-Log "ERROR in $functionName : $_" -Level ERROR
            $failedCount++
        }
    }
    else {
        Write-Log "ERROR: Function $functionName not found" -Level ERROR
        $failedCount++
    }
    
    Write-Log "" -Level INFO
}

################################################################################
# SUMMARY
################################################################################

Write-LogSection "PHASE 6: Execution Summary"

Write-Log "Modules Executed: $executedCount" -Level SUCCESS
if ($failedCount -gt 0) {
    Write-Log "Modules with Errors: $failedCount" -Level WARNING
}
Write-Log "Log File: $logFile" -Level INFO

Close-Logging

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Execution Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""