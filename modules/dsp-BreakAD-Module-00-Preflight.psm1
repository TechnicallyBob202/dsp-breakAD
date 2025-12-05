################################################################################
##
## dsp-BreakAD-Module-00-Preflight.psm1
##
## Preflight Setup - Environment Preparation
##
## Phases:
## 0: Create OU structure for breakAD objects
## 1: Validate environment and prerequisites
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0 - Preflight setup
##
################################################################################

function Invoke-ModulePreflight {
    <#
    .SYNOPSIS
        Preflight setup and environment preparation
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $config = $Environment.Config
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 00: Preflight Setup" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 0: CREATE ORGANIZATIONAL UNITS
    ################################################################################
    
    Write-Log "PHASE 0: Create Organizational Unit Structure" -Level INFO
    
    $domainDN = $domain.DistinguishedName
    $rootOUName = $config['BreakAD_RootOU']
    $usersOUName = $config['BreakAD_UsersOU']
    $computersOUName = $config['BreakAD_ComputersOU']
    
    $rootOUPath = "OU=$rootOUName,$domainDN"
    
    # Create root OU
    Write-Log "  Creating/verifying root OU: $rootOUName" -Level INFO
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$rootOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
        try {
            New-ADOrganizationalUnit -Name $rootOUName -Path $domainDN -ErrorAction Stop | Out-Null
            Write-Log "    [+] Created" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error creating root OU: $_" -Level ERROR
            return $false
        }
    }
    else {
        Write-Log "    [+] Already exists" -Level SUCCESS
    }
    
    # Create users OU
    Write-Log "  Creating/verifying users OU: $usersOUName" -Level INFO
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$usersOUName'" -SearchBase $rootOUPath -ErrorAction SilentlyContinue)) {
        try {
            New-ADOrganizationalUnit -Name $usersOUName -Path $rootOUPath -ErrorAction Stop | Out-Null
            Write-Log "    [+] Created" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error creating users OU: $_" -Level ERROR
            return $false
        }
    }
    else {
        Write-Log "    [+] Already exists" -Level SUCCESS
    }
    
    # Create computers OU
    Write-Log "  Creating/verifying computers OU: $computersOUName" -Level INFO
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$computersOUName'" -SearchBase $rootOUPath -ErrorAction SilentlyContinue)) {
        try {
            New-ADOrganizationalUnit -Name $computersOUName -Path $rootOUPath -ErrorAction Stop | Out-Null
            Write-Log "    [+] Created" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error creating computers OU: $_" -Level ERROR
            return $false
        }
    }
    else {
        Write-Log "    [+] Already exists" -Level SUCCESS
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 1: VALIDATE ENVIRONMENT
    ################################################################################
    
    Write-Log "PHASE 1: Validate Environment" -Level INFO
    
    # Check admin rights
    Write-Log "  Checking administrator privileges..." -Level INFO
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Log "    [!] Administrator privileges required" -Level ERROR
        return $false
    }
    Write-Log "    [+] Administrator rights verified" -Level SUCCESS
    
    # Check PowerShell version
    Write-Log "  Checking PowerShell version..." -Level INFO
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        Write-Log "    [!] PowerShell 5.1+ required (current: $($PSVersionTable.PSVersion))" -Level ERROR
        return $false
    }
    Write-Log "    [+] PowerShell version: $($PSVersionTable.PSVersion)" -Level SUCCESS
    
    # Verify AD module loaded
    Write-Log "  Checking ActiveDirectory module..." -Level INFO
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        try {
            Import-Module ActiveDirectory -ErrorAction Stop | Out-Null
            Write-Log "    [+] ActiveDirectory module loaded" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Failed to load ActiveDirectory module: $_" -Level ERROR
            return $false
        }
    }
    else {
        Write-Log "    [+] ActiveDirectory module already loaded" -Level SUCCESS
    }
    
    # Verify AD connectivity
    Write-Log "  Checking Active Directory connectivity..." -Level INFO
    try {
        $adTest = Get-ADDomain -ErrorAction Stop
        Write-Log "    [+] AD domain: $($adTest.Name)" -Level SUCCESS
    }
    catch {
        Write-Log "    [!] AD connectivity failed: $_" -Level ERROR
        return $false
    }
    
    # Verify Domain Controllers are reachable
    Write-Log "  Checking Domain Controller reachability..." -Level INFO
    try {
        $dcTest = Get-ADDomainController -Filter * -ErrorAction Stop
        if ($dcTest.Count -eq 0) {
            Write-Log "    [!] No Domain Controllers found" -Level ERROR
            return $false
        }
        Write-Log "    [+] Found $($dcTest.Count) Domain Controller(s)" -Level SUCCESS
    }
    catch {
        Write-Log "    [!] Domain Controller check failed: $_" -Level ERROR
        return $false
    }
    
    # Check replication health
    Write-Log "  Checking replication health..." -Level INFO
    try {
        $replHealth = Get-ADReplicationFailure -Scope Forest -ErrorAction SilentlyContinue
        if ($replHealth.Count -gt 0) {
            Write-Log "    [!] Replication issues detected - proceed with caution" -Level WARNING
        }
        else {
            Write-Log "    [+] Replication health verified" -Level SUCCESS
        }
    }
    catch {
        Write-Log "    [!] Could not check replication: $_" -Level WARNING
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 2: DISCOVER DOMAIN INFORMATION
    ################################################################################
    
    Write-Log "PHASE 2: Discover Domain Information" -Level INFO
    
    try {
        $discoveredDomain = Get-ADDomain -ErrorAction Stop
        $discoveredDCs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        if ($discoveredDCs -is [array]) {
            $discoveredPrimaryDC = $discoveredDCs[0]
        }
        else {
            $discoveredPrimaryDC = $discoveredDCs
        }
        
        Write-Log "  Domain: $($discoveredDomain.Name)" -Level SUCCESS
        Write-Log "  Domain DN: $($discoveredDomain.DistinguishedName)" -Level SUCCESS
        Write-Log "  Forest: $($discoveredDomain.Forest)" -Level SUCCESS
        Write-Log "  Primary DC: $($discoveredPrimaryDC.HostName)" -Level SUCCESS
        
        # Update environment object with discovered info
        $Environment.Domain = $discoveredDomain
        $Environment.DomainController = $discoveredPrimaryDC
    }
    catch {
        Write-Log "  [!] Failed to discover domain information: $_" -Level ERROR
        return $false
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # COMPLETION
    ################################################################################
    
    Write-Log "========================================" -Level INFO
    Write-Log "Module 00: Preflight Setup" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Status: COMPLETE" -Level SUCCESS
    Write-Log "" -Level INFO
    
    return $true
}

Export-ModuleMember -Function Invoke-ModulePreflight