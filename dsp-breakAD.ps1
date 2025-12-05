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
    [ValidateSet('Preflight', 'InfrastructureSecurity', 'AccountSecurity', 'ADDelegation', 'KerberosSecurity', 'GroupPolicySecurity')]
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

################################################################################
# LOAD CONFIGURATION
################################################################################

Write-LogSection "PHASE 1: Load Configuration"

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

################################################################################
# MODULE SELECTION
################################################################################

################################################################################
# RUN PREFLIGHT
################################################################################

Write-LogSection "PHASE 2: Run Preflight"

if (-not $SkipPreflight) {
    # Load preflight module first
    $preflightModule = Join-Path $Script:ModulesPath "dsp-BreakAD-Module-00-Preflight.psm1"
    if (Test-Path $preflightModule) {
        try {
            Import-Module $preflightModule -Force -ErrorAction Stop | Out-Null
            Write-Log "Loaded: Preflight" -Level SUCCESS
            
            # Get domain and DC first for Environment
            $domain = Get-ADDomain -ErrorAction Stop
            $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
            
            if ($dcs -is [array]) {
                $primaryDC = $dcs[0]
            }
            else {
                $primaryDC = $dcs
            }
            
            # Build environment for preflight
            $Environment = @{
                Domain = $domain
                DomainController = $primaryDC
                Config = $config
            }
            
            $preflightResult = Invoke-ModulePreflight -Environment $Environment -ErrorAction Stop
            
            if ($preflightResult) {
                Write-Log "Preflight - COMPLETE" -Level SUCCESS
            }
            else {
                Write-Log "ERROR: Preflight validation failed" -Level ERROR
                exit 1
            }
        }
        catch {
            Write-Log "ERROR: Preflight execution failed: $_" -Level ERROR
            exit 1
        }
    }
    else {
        Write-Log "ERROR: Preflight module not found" -Level ERROR
        exit 1
    }
}
else {
    Write-Log "Preflight skipped" -Level INFO
}

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
    Write-Log "Running all modules" -Level INFO
}
elseif ($ModuleNames.Count -gt 0) {
    foreach ($moduleName in $ModuleNames) {
        if ($moduleName -in $availableModules) {
            $selectedModules += $moduleName
        }
        else {
            Write-Log "WARNING: Unknown module: $moduleName" -Level WARNING
        }
    }
    Write-Log "Selected modules: $($selectedModules -join ', ')" -Level INFO
}
else {
    Write-Log "Available modules:" -Level INFO
    for ($i = 0; $i -lt $availableModules.Count; $i++) {
        Write-Host "  $($i+1)) $($availableModules[$i])"
    }
    Write-Host ""
    $selection = Read-Host "Select modules to run (comma-separated numbers, or 0 for all)"
    
    if ($selection -eq "0") {
        $selectedModules = $availableModules
    }
    else {
        $selections = $selection -split "," | ForEach-Object { $_.Trim() }
        foreach ($sel in $selections) {
            if ([int]::TryParse($sel, [ref]$null)) {
                $index = [int]$sel - 1
                if ($index -ge 0 -and $index -lt $availableModules.Count) {
                    $selectedModules += $availableModules[$index]
                }
            }
        }
    }
    
    Write-Log "Selected modules via interactive prompt: $($selectedModules -join ', ')" -Level INFO
}

if ($selectedModules.Count -eq 0) {
    Write-Log "ERROR: No modules selected" -Level ERROR
    exit 1
}

Write-Log "Selected $($selectedModules.Count) module(s)" -Level SUCCESS

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
    # Extract module name from filename: dsp-BreakAD-Module-01-InfrastructureSecurity.psm1 -> InfrastructureSecurity
    $moduleName = $moduleFile.BaseName -replace "dsp-BreakAD-Module-\d+-", ""
    
    # Skip Preflight - already ran
    if ($moduleName -eq "Preflight") {
        continue
    }
    
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

if ($loadedModules.Count -eq 0) {
    Write-Log "ERROR: No modules loaded successfully" -Level ERROR
    exit 1
}

Write-Log "Successfully loaded $($loadedModules.Count) module(s)" -Level SUCCESS

################################################################################
# BUILD ENVIRONMENT OBJECT
################################################################################

Write-LogSection "PHASE 5: Build Environment"

# Environment already populated by Preflight - just reuse it
Write-Log "Environment object ready (populated by Preflight)" -Level SUCCESS

################################################################################
# EXECUTE MODULES
################################################################################

Write-LogSection "PHASE 6: Execute Modules"

$executedCount = 0
$failedCount = 0

foreach ($moduleName in $loadedModules) {
    Write-Log "" -Level INFO
    Write-Log "Executing: $moduleName" -Level INFO
    Write-Log "" -Level INFO
    
    try {
        # Convert module name to function name: Preflight -> Invoke-ModulePreflight
        $functionName = "Invoke-Module$(($moduleName -replace '\s+', '') -replace '-', '')"
        
        # Try to call the function
        if (Get-Command $functionName -ErrorAction SilentlyContinue) {
            & $functionName -Environment $Environment -ErrorAction Stop
            Write-Log "$moduleName - COMPLETE" -Level SUCCESS
            $executedCount++
        }
        else {
            Write-Log "ERROR: Function $functionName not found" -Level ERROR
            $failedCount++
        }
    }
    catch {
        Write-Log "ERROR executing $moduleName : $_" -Level ERROR
        $failedCount++
    }
}

################################################################################
# EXECUTION SUMMARY
################################################################################

Write-LogSection "PHASE 7: Execution Summary"

Write-Log "Modules executed: $executedCount" -Level INFO
Write-Log "Modules failed: $failedCount" -Level INFO

if ($failedCount -gt 0) {
    Write-Log "WARNING: Some modules failed to execute" -Level WARNING
}

Write-Log "" -Level INFO
Write-Log "=== dsp-breakAD Execution Completed ===" -Level INFO
Write-Log "Log file: $logFile" -Level INFO

# Close logging
if (Get-Command Close-Logging -ErrorAction SilentlyContinue) {
    Close-Logging
}