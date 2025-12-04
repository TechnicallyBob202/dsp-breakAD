################################################################################
##
## dsp-BreakAD-MainScript.ps1
##
## Main orchestration script for breaking Active Directory configurations
## 
## Executes 8 modules in sequence that apply security misconfigurations
## to demonstrate bad AD practices and security risks.
##
## Linear flow:
## 1. Preflight checks (environment validation)
## 2. Module discovery (load modules from modules folder)
## 3. Sequential execution (run modules 01-08 in order)
##
## Version: 1.0.0-20251204
##
################################################################################

#Requires -Version 5.1
#Requires -Modules ActiveDirectory
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$ModulesPath,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath
)

$ErrorActionPreference = "Continue"

################################################################################
# INITIALIZATION
################################################################################

$Script:ScriptPath = $PSScriptRoot
$Script:ModulesFolder = if ($ModulesPath) { 
    $ModulesPath 
} 
else { 
    Join-Path $ScriptPath "modules"
}

if (-not (Test-Path $Script:ModulesFolder)) {
    Write-Host "ERROR: Modules folder not found at $($Script:ModulesFolder)" -ForegroundColor Red
    exit 1
}

################################################################################
# COLORS
################################################################################

$Colors = @{
    Header = 'Cyan'
    Section = 'Green'
    Success = 'Green'
    Warning = 'Yellow'
    Error = 'Red'
    Info = 'White'
}

################################################################################
# OUTPUT FUNCTIONS
################################################################################

function Write-Status {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $color = $Colors[$Level]
    $prefix = switch ($Level) {
        'Info' { '[*]' }
        'Success' { '[+]' }
        'Warning' { '[!]' }
        'Error' { '[X]' }
    }
    
    Write-Host "$prefix $Message" -ForegroundColor $color
}

function Write-Header {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Text
    )
    
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor $Colors.Header
    Write-Host $Text -ForegroundColor $Colors.Header
    Write-Host "================================================================================" -ForegroundColor $Colors.Header
    Write-Host ""
}

################################################################################
# PREFLIGHT CHECKS
################################################################################

function Test-PreflightEnvironment {
    Write-Header "PREFLIGHT CHECKS"
    
    $preflight_ok = $true
    
    # Check PowerShell version
    Write-Status "Checking PowerShell version..." -Level Info
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Status "PowerShell 5.1+ required (you have $($PSVersionTable.PSVersion))" -Level Error
        $preflight_ok = $false
    } else {
        Write-Status "PowerShell version: $($PSVersionTable.PSVersion)" -Level Success
    }
    
    # Check AD module
    Write-Status "Checking Active Directory module..." -Level Info
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Status "Active Directory module not available" -Level Error
        $preflight_ok = $false
    } else {
        Import-Module ActiveDirectory -ErrorAction SilentlyContinue
        Write-Status "Active Directory module loaded" -Level Success
    }
    
    # Check admin rights
    Write-Status "Checking administrator privileges..." -Level Info
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Status "Administrator privileges required" -Level Error
        $preflight_ok = $false
    } else {
        Write-Status "Running as administrator" -Level Success
    }
    
    # Discover domain
    Write-Status "Discovering domain information..." -Level Info
    try {
        $domain = Get-ADDomain -Current LocalComputer -ErrorAction Stop
        Write-Status "Domain: $($domain.Name)" -Level Success
        Write-Status "Forest: $((Get-ADForest -Current LocalComputer).Name)" -Level Success
        
        $dc = Get-ADDomainController -DomainName $domain.Name -Discover -ErrorAction Stop
        Write-Status "Domain Controller: $($dc.HostName)" -Level Success
    }
    catch {
        Write-Status "Failed to discover domain: $_" -Level Error
        $preflight_ok = $false
    }
    
    Write-Host ""
    
    if (-not $preflight_ok) {
        Write-Status "PREFLIGHT FAILED - aborting" -Level Error
        exit 1
    }
    
    Write-Status "PREFLIGHT CHECKS PASSED" -Level Success
    Write-Host ""
    
    return @{
        Domain = $domain
        DomainController = $dc
    }
}

################################################################################
# MODULE DISCOVERY & LOADING
################################################################################

function Get-BreakADModules {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ModulesFolder
    )
    
    Write-Header "DISCOVERING MODULES"
    
    $modules = @()
    
    # Find all module files numbered 01-08
    $moduleFiles = Get-ChildItem -Path $ModulesFolder -Filter "*.psm1" | 
        Where-Object { $_.Name -match 'dsp-BreakAD-Module-(\d+)' } |
        Sort-Object { 
            [int]($_.Name -replace '.*-(\d+).*', '$1')
        }
    
    if ($moduleFiles.Count -eq 0) {
        Write-Status "No modules found in $ModulesFolder" -Level Warning
        return $modules
    }
    
    foreach ($file in $moduleFiles) {
        # Extract module number
        if ($file.Name -match 'dsp-BreakAD-Module-(\d+)') {
            $moduleNum = [int]$matches[1]
            
            # Extract function name from filename
            # dsp-BreakAD-Module-01-BadActors.psm1 -> Invoke-BadActors
            if ($file.Name -match 'dsp-BreakAD-Module-\d+-(.+)\.psm1') {
                $functionName = 'Invoke-' + ($matches[1] -replace '-', '')
                
                $modules += @{
                    Number = $moduleNum
                    Path = $file.FullName
                    Name = $file.BaseName
                    FunctionName = $functionName
                    FileName = $file.Name
                }
                
                Write-Status "Found module $moduleNum`: $($file.Name)" -Level Info
            }
        }
    }
    
    Write-Host ""
    Write-Status "Total modules discovered: $($modules.Count)" -Level Success
    Write-Host ""
    
    return $modules
}

################################################################################
# MODULE EXECUTION
################################################################################

function Invoke-BreakADModule {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Module,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    Write-Host ""
    Write-Host "────────────────────────────────────────────────────────────────────────────────" -ForegroundColor $Colors.Section
    Write-Status "Executing Module $($Module.Number): $($Module.Name)" -Level Info
    Write-Host "────────────────────────────────────────────────────────────────────────────────" -ForegroundColor $Colors.Section
    Write-Host ""
    
    try {
        # Remove any previously loaded version
        Remove-Module $Module.Name -Force -ErrorAction SilentlyContinue
        
        # Import the module
        Import-Module $Module.Path -Force -ErrorAction Stop
        
        # Get the function
        $function = Get-Command $Module.FunctionName -ErrorAction Stop
        
        if (-not $function) {
            Write-Status "Function $($Module.FunctionName) not found in module" -Level Error
            return $false
        }
        
        # Execute the function
        & $Module.FunctionName -Environment $Environment
        
        Write-Status "Module $($Module.Number) completed successfully" -Level Success
        
        # Clean up
        Remove-Module $Module.Name -Force -ErrorAction SilentlyContinue
        
        return $true
    }
    catch {
        Write-Status "Module $($Module.Number) failed: $_" -Level Error
        Write-Host $_.Exception.Message -ForegroundColor $Colors.Error
        return $false
    }
}

################################################################################
# MAIN EXECUTION
################################################################################

function Main {
    Clear-Host
    
    Write-Host ""
    Write-Host "╔════════════════════════════════════════════════════════════════════════════════╗" -ForegroundColor $Colors.Header
    Write-Host "║                     dsp-BreakAD: AD Misconfiguration Demo                     ║" -ForegroundColor $Colors.Header
    Write-Host "║                                                                                ║" -ForegroundColor $Colors.Header
    Write-Host "║  This script applies security misconfigurations to Active Directory to        ║" -ForegroundColor $Colors.Header
    Write-Host "║  demonstrate common AD security risks and bad practices.                      ║" -ForegroundColor $Colors.Header
    Write-Host "║                                                                                ║" -ForegroundColor $Colors.Header
    Write-Host "║  Version: 1.0.0-20251204                                                      ║" -ForegroundColor $Colors.Header
    Write-Host "╚════════════════════════════════════════════════════════════════════════════════╝" -ForegroundColor $Colors.Header
    Write-Host ""
    
    # Preflight checks
    $environment = Test-PreflightEnvironment
    
    # Discover modules
    $modules = Get-BreakADModules -ModulesFolder $Script:ModulesFolder
    
    if ($modules.Count -eq 0) {
        Write-Status "No modules found - nothing to execute" -Level Warning
        exit 1
    }
    
    # Execute modules in sequence
    Write-Header "EXECUTING MODULES"
    
    $successCount = 0
    $failureCount = 0
    
    foreach ($module in $modules) {
        $result = Invoke-BreakADModule -Module $module -Environment $environment
        
        if ($result) {
            $successCount++
        } else {
            $failureCount++
        }
        
        # Pause between modules
        Start-Sleep -Seconds 1
    }
    
    # Summary
    Write-Header "EXECUTION SUMMARY"
    
    Write-Status "Total modules: $($modules.Count)" -Level Info
    Write-Status "Successful: $successCount" -Level Success
    Write-Status "Failed: $failureCount" -Level $(if ($failureCount -gt 0) { 'Warning' } else { 'Success' })
    
    Write-Host ""
    
    if ($failureCount -eq 0) {
        Write-Status "ALL MODULES COMPLETED SUCCESSFULLY" -Level Success
    } else {
        Write-Status "SOME MODULES FAILED - CHECK OUTPUT ABOVE" -Level Warning
    }
    
    Write-Host ""
}

# Execute main
Main