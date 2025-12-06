################################################################################
##
## dsp-breakAD.ps1
##
## Main orchestration script for dsp-breakAD - 2-Level Menu Architecture
## Applies intentional AD misconfigurations for DSP demonstration
##
## Level 1: Select security category
## Level 2: Select specific IOEs within that category
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 2.0.0
##
################################################################################

#Requires -Version 5.1
#Requires -RunAsAdministrator

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('InfrastructureSecurity', 'AccountSecurity', 'GroupPolicySecurity', 'ADDelegation', 'KerberosSecurity', 'Hybrid')]
    [string]$Category,
    
    [Parameter(Mandatory=$false)]
    [int[]]$IOEs,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipPreflight,
    
    [Parameter(Mandatory=$false)]
    [switch]$All
)

$ErrorActionPreference = "Continue"

################################################################################
# INITIALIZATION
################################################################################

$Script:ScriptPath = $PSScriptRoot
$Script:ModulesPath = Join-Path $ScriptPath "modules"
$Script:ConfigPath = Join-Path $ScriptPath "dsp-breakAD.config"
$Script:LogsPath = Join-Path $ScriptPath "logs"

# Create logs directory if it doesn't exist
if (-not (Test-Path $Script:LogsPath)) {
    New-Item -ItemType Directory -Path $Script:LogsPath -Force | Out-Null
}

# Import logging module first
$loggingModule = Join-Path $ScriptPath "dsp-BreakAD-Logging.psm1"
if (-not (Test-Path $loggingModule)) {
    Write-Host "ERROR: Logging module not found at $loggingModule" -ForegroundColor Red
    exit 1
}

try {
    Import-Module $loggingModule -Force -ErrorAction Stop | Out-Null
}
catch {
    Write-Host "ERROR: Failed to load logging module: $_" -ForegroundColor Red
    exit 1
}

# Initialize logging
$logFile = Initialize-Logging -LogsDirectory $Script:LogsPath

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  dsp-breakAD - Security Misconfiguration" -ForegroundColor Cyan
Write-Host "  Version 2.0.0 (2-Level Menu)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Log "=== dsp-breakAD Execution Started ===" -Level INFO
Write-Log "Script Path: $Script:ScriptPath" -Level INFO
Write-Log "Log File: $logFile" -Level INFO

################################################################################
# DEFINE SECURITY CATEGORIES & IOEs
################################################################################

# Define all available categories and their IOEs
$SecurityCategories = @{
    "InfrastructureSecurity" = @{
        Name = "AD Infrastructure Security"
        Description = "Registry modifications, Print Spooler, DNS, schema permissions"
        IOEs = @{
            1  = "Enable Print Spooler on all Domain Controllers"
            2  = "Disable LDAP Signing on Domain Controllers"
            3  = "Disable LDAP Channel Binding on Domain Controllers"
            4  = "Allow Null Session to Domain Controllers"
            5  = "Modify schema permissions (increase AllExtendedRights)"
            6  = "Weaken DNS permissions in _msdcs zone"
            7  = "Enable SMB v1 on Domain Controllers"
            8  = "Disable SMB Signing on Domain Controllers"
            9  = "Configure dangerous dSHeuristics settings"
        }
    }
    
    "AccountSecurity" = @{
        Name = "Account Security"
        Description = "Weak account configurations, privilege settings, encryption"
        IOEs = @{
            1  = "Create privileged accounts with weak passwords"
            2  = "Create accounts with password never expires"
            3  = "Create accounts with empty password (DES encryption)"
            4  = "Create accounts with reversible password encryption"
            5  = "Create accounts with DONT_EXPIRE_PASSWORD flag"
            6  = "Create accounts with DONT_REQUIRE_PREAUTH flag"
            7  = "Create accounts with TRUSTED_FOR_DELEGATION flag"
            8  = "Create accounts in privileged groups (Domain Admins, etc)"
            9  = "Create smart card accounts with old passwords"
            10 = "Create recently privileged accounts"
            11 = "Create recently modified accounts"
            12 = "Create accounts with weak Fine-Grained Password Policy"
            13 = "Create service accounts with plaintext passwords in description"
        }
    }
    
    "GroupPolicySecurity" = @{
        Name = "Group Policy Security"
        Description = "Dangerous GPO settings, weak policies, delegation abuse"
        IOEs = @{
            1  = "Create GPO with dangerous user rights assignments"
            2  = "Create GPO with reversible password storage enabled"
            3  = "Create GPO with writable shortcuts configured"
            4  = "Create GPO with dangerous logon script paths"
            5  = "Create GPO with weak LM hash storage enabled"
            6  = "Create GPO with scheduled tasks configured"
            7  = "Link GPO at Domain level with dangerous settings"
            8  = "Link GPO at Site level with dangerous settings"
            9  = "Link GPO at Domain Controller OU level"
            10 = "Grant GPO linking delegation at domain level"
            11 = "Grant GPO linking delegation at site level"
            12 = "Grant GPO linking delegation at DC OU level"
        }
    }
    
    "ADDelegation" = @{
        Name = "AD Delegation"
        Description = "Excessive delegation, abuse-prone permissions, dangerous ACLs"
        IOEs = @{
            1  = "Grant CreateChild permission to Everyone"
            2  = "Grant ResetPassword permission to non-admins"
            3  = "Grant WriteDACL permission on sensitive OUs"
            4  = "Grant WriteProperty on sensitive attributes"
            5  = "Grant GenericAll on computer objects to service accounts"
            6  = "Grant GenericAll on user objects to service accounts"
            7  = "Grant AllExtendedRights on sensitive OUs"
            8  = "Create overly permissive delegation chains"
            9  = "Grant modify delegation permissions to non-admins"
            10 = "Create accounts with dangerous delegation rights"
        }
    }
    
    "KerberosSecurity" = @{
        Name = "Kerberos Security"
        Description = "Weak Kerberos settings, encryption downgrades, trust weaknesses"
        IOEs = @{
            1  = "Disable Kerberos pre-authentication on accounts"
            2  = "Enable weak DES encryption on accounts"
            3  = "Create trust relationships with weak security options"
            4  = "Disable mutual authentication requirements"
            5  = "Allow RC4 HMAC encryption on critical accounts"
            6  = "Misconfigure SPNs (duplicate or dangerous SPNs)"
            7  = "Enable unconstrained delegation on sensitive accounts"
            8  = "Create accounts with weak Kerberos encryption settings"
            9  = "Weaken domain functional level settings"
            10 = "Disable Kerberos armoring (channel binding)"
        }
    }
    
    "Hybrid" = @{
        Name = "Hybrid/Cross-Category"
        Description = "Combinations of issues across multiple categories"
        IOEs = @{
            1  = "Create compromised admin account (all weak settings)"
            2  = "Create service account with dangerous delegation + weak Kerberos"
            3  = "Configure infrastructure + policy security issues together"
            4  = "Create delegation chain exploit scenario"
            5  = "Create golden ticket simulation scenario"
            6  = "Create kerberoasting scenario"
        }
    }
}

################################################################################
# PHASE 1: PREFLIGHT CHECKS
################################################################################

Write-Log "PHASE 1: Preflight Validation" -Level INFO
Write-Log "" -Level INFO

# Check if preflight was already run or skip requested
if (-not $SkipPreflight) {
    $preflightModule = Join-Path $Script:ModulesPath "dsp-BreakAD-Module-00-Preflight.psm1"
    
    if (Test-Path $preflightModule) {
        try {
            Import-Module $preflightModule -Force -ErrorAction Stop | Out-Null
            
            # Load config file
            $config = @{}
            if (Test-Path $Script:ConfigPath) {
                $configContent = Get-Content $Script:ConfigPath -Raw
                $configContent = $configContent | Select-String '^\s*[^#\s]' | ForEach-Object { $_.Line }
                foreach ($line in $configContent) {
                    if ($line -match '^\s*([^=]+)=(.*)$') {
                        $config[$matches[1].Trim()] = $matches[2].Trim()
                    }
                }
            }
            
            $preflightResult = Invoke-ModulePreflight -SkipPreflight $SkipPreflight -Config $config
            
            if (-not $preflightResult) {
                Write-Log "ERROR: Preflight validation failed" -Level ERROR
                exit 1
            }
            
            Write-Log "Preflight validation passed" -Level SUCCESS
        }
        catch {
            Write-Log "ERROR: Preflight execution failed: $_" -Level ERROR
            exit 1
        }
    }
    else {
        Write-Log "WARNING: Preflight module not found, skipping validation" -Level WARNING
    }
}
else {
    Write-Log "Preflight validation skipped" -Level INFO
}

Write-Log "" -Level INFO

################################################################################
# PHASE 2: CATEGORY & IOE SELECTION (2-LEVEL MENU)
################################################################################

Write-LogSection "PHASE 2: Security Category & IOE Selection"

$selectedCategory = $null
$selectedIOEs = @()

# LEVEL 1: SELECT CATEGORY
if ($Category) {
    if ($SecurityCategories.ContainsKey($Category)) {
        $selectedCategory = $Category
        Write-Log "Category selected via parameter: $Category" -Level INFO
    }
    else {
        Write-Log "ERROR: Invalid category: $Category" -Level ERROR
        exit 1
    }
}
else {
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  LEVEL 1: SELECT SECURITY CATEGORY                         ║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    $catIndex = 1
    $categoryList = @()
    
    foreach ($catKey in @("InfrastructureSecurity", "AccountSecurity", "GroupPolicySecurity", "ADDelegation", "KerberosSecurity", "Hybrid")) {
        $cat = $SecurityCategories[$catKey]
        Write-Host "  $catIndex) $($cat.Name)"
        Write-Host "     $($cat.Description)"
        Write-Host ""
        $categoryList += $catKey
        $catIndex++
    }
    
    Write-Host "  0) Exit"
    Write-Host ""
    
    $catSelection = Read-Host "Select category (0-6)"
    
    if ($catSelection -eq "0") {
        Write-Log "User exited script" -Level INFO
        exit 0
    }
    
    if ([int]::TryParse($catSelection, [ref]$null)) {
        $catIndex = [int]$catSelection - 1
        if ($catIndex -ge 0 -and $catIndex -lt $categoryList.Count) {
            $selectedCategory = $categoryList[$catIndex]
            Write-Log "User selected category: $selectedCategory" -Level INFO
        }
        else {
            Write-Log "ERROR: Invalid category selection" -Level ERROR
            exit 1
        }
    }
    else {
        Write-Log "ERROR: Invalid input" -Level ERROR
        exit 1
    }
}

Write-Host ""

# LEVEL 2: SELECT IOEs WITHIN CATEGORY
if ($IOEs.Count -gt 0) {
    $catIOEs = $SecurityCategories[$selectedCategory].IOEs
    foreach ($ioeNum in $IOEs) {
        if ($catIOEs.ContainsKey($ioeNum)) {
            $selectedIOEs += $ioeNum
            Write-Log "IOE selected via parameter: $selectedCategory - IOE $ioeNum" -Level INFO
        }
        else {
            Write-Log "WARNING: Invalid IOE number for $selectedCategory : $ioeNum" -Level WARNING
        }
    }
    
    if ($selectedIOEs.Count -eq 0) {
        Write-Log "ERROR: No valid IOEs selected" -Level ERROR
        exit 1
    }
}
elseif ($All) {
    $catIOEs = $SecurityCategories[$selectedCategory].IOEs
    $selectedIOEs = $catIOEs.Keys | Sort-Object
    Write-Log "All IOEs selected for category: $selectedCategory" -Level INFO
}
else {
    $catInfo = $SecurityCategories[$selectedCategory]
    $catIOEs = $catInfo.IOEs
    
    Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║  LEVEL 2: SELECT IOES FOR $($catInfo.Name.ToUpper().PadRight(43))║" -ForegroundColor Cyan
    Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($ioeNum in ($catIOEs.Keys | Sort-Object)) {
        Write-Host "  $($ioeNum.ToString().PadLeft(2))) $($catIOEs[$ioeNum])"
    }
    
    Write-Host ""
    Write-Host "  0) Back to category selection"
    Write-Host ""
    
    $ioeSelection = Read-Host "Select IOEs (comma-separated numbers, or 0 for all)"
    
    if ($ioeSelection -eq "0") {
        $selectedIOEs = $catIOEs.Keys | Sort-Object
        Write-Log "User selected all IOEs for category: $selectedCategory" -Level INFO
    }
    else {
        $ioeParts = $ioeSelection -split "," | ForEach-Object { $_.Trim() }
        foreach ($part in $ioeParts) {
            if ([int]::TryParse($part, [ref]$null)) {
                $ioeNum = [int]$part
                if ($catIOEs.ContainsKey($ioeNum)) {
                    $selectedIOEs += $ioeNum
                }
                else {
                    Write-Host "  WARNING: IOE $ioeNum not found in this category" -ForegroundColor Yellow
                }
            }
        }
        
        if ($selectedIOEs.Count -eq 0) {
            Write-Log "ERROR: No valid IOEs selected" -Level ERROR
            exit 1
        }
        
        Write-Log "User selected IOEs for $selectedCategory : $($selectedIOEs -join ',')" -Level INFO
    }
}

Write-Host ""
Write-Host "Selected: $selectedCategory - IOEs: $($selectedIOEs -join ', ')" -ForegroundColor Green
Write-Host ""
Write-Log "Selection Summary: Category=$selectedCategory, IOEs=$($selectedIOEs -join ',')" -Level SUCCESS

Write-Log "" -Level INFO

################################################################################
# PHASE 3: CONFIRMATION & EXECUTION PLANNING
################################################################################

Write-LogSection "PHASE 3: Execution Planning"

$selectedIOEDescriptions = @()
$catIOEs = $SecurityCategories[$selectedCategory].IOEs

foreach ($ioeNum in ($selectedIOEs | Sort-Object)) {
    $selectedIOEDescriptions += "  IOE $ioeNum : $($catIOEs[$ioeNum])"
}

Write-Host "Will execute the following IOE misconfigurations:" -ForegroundColor Yellow
Write-Host ""
foreach ($desc in $selectedIOEDescriptions) {
    Write-Host $desc
}
Write-Host ""

$confirm = Read-Host "Continue with execution? (yes/no)"

if ($confirm -ne "yes" -and $confirm -ne "y") {
    Write-Log "User cancelled execution" -Level INFO
    Write-Host ""
    Write-Host "Execution cancelled." -ForegroundColor Yellow
    exit 0
}

Write-Log "User confirmed execution" -Level SUCCESS
Write-Log "" -Level INFO

################################################################################
# PHASE 4: MODULE EXECUTION
################################################################################

Write-LogSection "PHASE 4: Module Execution"

# Load and execute the appropriate module based on selected category
$moduleName = "dsp-BreakAD-Module-*-$selectedCategory.psm1"
$moduleFile = Get-ChildItem -Path $Script:ModulesPath -Filter $moduleName -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $moduleFile) {
    Write-Log "ERROR: Module for $selectedCategory not found" -Level ERROR
    Write-Host "ERROR: Cannot find module for category: $selectedCategory" -ForegroundColor Red
    exit 1
}

Write-Log "Loading module: $($moduleFile.Name)" -Level INFO

try {
    Import-Module $moduleFile.FullPath -Force -ErrorAction Stop | Out-Null
    Write-Log "Module loaded successfully" -Level SUCCESS
}
catch {
    Write-Log "ERROR: Failed to load module: $_" -Level ERROR
    exit 1
}

# Extract function name from module
# dsp-BreakAD-Module-01-InfrastructureSecurity.psm1 → Invoke-ModuleInfrastructureSecurity
$functionName = "Invoke-Module" + $selectedCategory
$functionExists = Get-Command -Name $functionName -ErrorAction SilentlyContinue

if (-not $functionExists) {
    Write-Log "ERROR: Function $functionName not found in module" -Level ERROR
    Write-Host "ERROR: Cannot find function: $functionName" -ForegroundColor Red
    exit 1
}

Write-Log "Executing function: $functionName with IOEs: $($selectedIOEs -join ',')" -Level INFO

try {
    $executionResult = & $functionName -SelectedIOEs $selectedIOEs -Config $config
    
    if ($executionResult -eq $false) {
        Write-Log "WARNING: Module execution completed with errors" -Level WARNING
    }
    else {
        Write-Log "Module execution completed successfully" -Level SUCCESS
    }
}
catch {
    Write-Log "ERROR: Module execution failed: $_" -Level ERROR
    exit 1
}

Write-Log "" -Level INFO

################################################################################
# PHASE 5: EXECUTION SUMMARY
################################################################################

Write-LogSection "PHASE 5: Execution Summary"

Write-Host "╔════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║  EXECUTION COMPLETED                                       ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Host "Category: $selectedCategory" -ForegroundColor Cyan
Write-Host "IOEs Applied: $($selectedIOEs.Count)" -ForegroundColor Cyan
Write-Host "Log File: $logFile" -ForegroundColor Cyan
Write-Host ""

Write-Log "=== dsp-breakAD Execution Completed ===" -Level INFO
Write-Log "Log saved to: $logFile" -Level INFO
Write-Log "" -Level INFO

################################################################################
# END OF SCRIPT
################################################################################