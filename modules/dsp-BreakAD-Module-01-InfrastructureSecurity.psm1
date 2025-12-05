################################################################################
##
## dsp-BreakAD-Module-01-InfrastructureSecurity.psm1
##
## Infrastructure Security Misconfigurations
##
## Module 1 creates infrastructure-level security weaknesses:
## - Creates dedicated bad user accounts (Schema Admin and Enterprise Admin users)
## - Adds users to privileged groups (Schema Admins, Enterprise Admins)
## - Enables Print Spooler on all Domain Controllers
## - Modifies dSHeuristics for dangerous settings
## - Optionally weakens AdminSDHolder protection
##
## User Creation (Idempotent):
## - Schema Admin users: break-SchemaAdmin-01, break-SchemaAdmin-02, etc.
## - Enterprise Admin users: break-EnterpriseAdmin-01, break-EnterpriseAdmin-02, etc.
## - All properties driven by config file for easy adjustment
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 2.0.0 - Reworked for Idempotency
##
################################################################################

function Invoke-ModuleInfrastructureSecurity {
    <#
    .SYNOPSIS
        Applies infrastructure security misconfigurations
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config info
        
    .DESCRIPTION
        Creates infrastructure-level security weaknesses:
        1. Creates Schema Admin and Enterprise Admin bad user accounts
        2. Adds users to their respective privileged groups
        3. Enables Print Spooler on all Domain Controllers
        4. Modifies dSHeuristics for anonymous access
        5. Optionally weakens AdminSDHolder
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    $successCount = 0
    $errorCount = 0
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Infrastructure Security Module Starting" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Domain: $($domain.Name)" -Level INFO
    Write-Log "DC: $($dc.HostName)" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 1: CREATE SCHEMA ADMIN USERS
    ################################################################################
    
    Write-Log "PHASE 1: Creating Schema Admin Users" -Level INFO
    Write-Log "" -Level INFO
    
    $schemaAdminCount = [int]$config['InfrastructureSecurity_SchemaAdminCount']
    $schemaAdminPassword = $config['InfrastructureSecurity_SchemaAdminPassword']
    $schemaAdminEnabled = $config['InfrastructureSecurity_SchemaAdminEnabled'] -eq 'true'
    $schemaAdminDescription = $config['InfrastructureSecurity_SchemaAdminDescription']
    
    $schemaAdminUsers = @()
    
    if ($schemaAdminCount -gt 0) {
        Write-Log "Creating $schemaAdminCount Schema Admin user(s)..." -Level INFO
        Write-Log "  Password source: config" -Level INFO
        Write-Log "  Enabled state: $schemaAdminEnabled" -Level INFO
        Write-Log "" -Level INFO
        
        $securePassword = ConvertTo-SecureString $schemaAdminPassword -AsPlainText -Force
        $domainDN = $domain.DistinguishedName
        
        for ($i = 1; $i -le $schemaAdminCount; $i++) {
            $userName = "break-SchemaAdmin-{0:D2}" -f $i
            
            try {
                # Check if user already exists
                $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
                
                if ($existingUser) {
                    Write-Log "  [*] User already exists: $userName" -Level INFO
                    
                    # Verify properties match config (idempotency)
                    $needsUpdate = $false
                    
                    if ($existingUser.Enabled -ne $schemaAdminEnabled) {
                        Write-Log "    Updating Enabled state: $($existingUser.Enabled) → $schemaAdminEnabled" -Level INFO
                        Set-ADUser -Identity $userName -Enabled $schemaAdminEnabled -ErrorAction Stop
                        $needsUpdate = $true
                    }
                    
                    if ($existingUser.Description -ne $schemaAdminDescription) {
                        Write-Log "    Updating Description" -Level INFO
                        Set-ADUser -Identity $userName -Description $schemaAdminDescription -ErrorAction Stop
                        $needsUpdate = $true
                    }
                    
                    if ($needsUpdate) {
                        Write-LogChange -Object $userName -Attribute "Properties" -OldValue "Various" -NewValue "Updated to config"
                    }
                    
                    $schemaAdminUsers += $existingUser
                    Write-Log "    [+] User verified/updated: $userName" -Level SUCCESS
                }
                else {
                    # Create new user
                    Write-Log "  Creating new user: $userName" -Level INFO
                    
                    New-ADUser `
                        -Name $userName `
                        -SamAccountName $userName `
                        -AccountPassword $securePassword `
                        -Enabled $schemaAdminEnabled `
                        -Description $schemaAdminDescription `
                        -ChangePasswordAtLogon $false `
                        -ErrorAction Stop
                    
                    Write-LogChange -Object $userName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
                    Write-Log "    [+] User created: $userName" -Level SUCCESS
                    
                    # Wait for replication
                    Start-Sleep -Milliseconds 500
                    
                    # Retrieve the created user
                    $user = Get-ADUser -Identity $userName -ErrorAction Stop
                    $schemaAdminUsers += $user
                }
                
                $successCount++
            }
            catch {
                Write-Log "    [!] Error with $userName : $_" -Level ERROR
                $errorCount++
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 2: CREATE ENTERPRISE ADMIN USERS
    ################################################################################
    
    Write-Log "PHASE 2: Creating Enterprise Admin Users" -Level INFO
    Write-Log "" -Level INFO
    
    $enterpriseAdminCount = [int]$config['InfrastructureSecurity_EnterpriseAdminCount']
    $enterpriseAdminPassword = $config['InfrastructureSecurity_EnterpriseAdminPassword']
    $enterpriseAdminEnabled = $config['InfrastructureSecurity_EnterpriseAdminEnabled'] -eq 'true'
    $enterpriseAdminDescription = $config['InfrastructureSecurity_EnterpriseAdminDescription']
    
    $enterpriseAdminUsers = @()
    
    if ($enterpriseAdminCount -gt 0) {
        Write-Log "Creating $enterpriseAdminCount Enterprise Admin user(s)..." -Level INFO
        Write-Log "  Password source: config" -Level INFO
        Write-Log "  Enabled state: $enterpriseAdminEnabled" -Level INFO
        Write-Log "" -Level INFO
        
        $securePassword = ConvertTo-SecureString $enterpriseAdminPassword -AsPlainText -Force
        $domainDN = $domain.DistinguishedName
        
        for ($i = 1; $i -le $enterpriseAdminCount; $i++) {
            $userName = "break-EnterpriseAdmin-{0:D2}" -f $i
            
            try {
                # Check if user already exists
                $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
                
                if ($existingUser) {
                    Write-Log "  [*] User already exists: $userName" -Level INFO
                    
                    # Verify properties match config (idempotency)
                    $needsUpdate = $false
                    
                    if ($existingUser.Enabled -ne $enterpriseAdminEnabled) {
                        Write-Log "    Updating Enabled state: $($existingUser.Enabled) → $enterpriseAdminEnabled" -Level INFO
                        Set-ADUser -Identity $userName -Enabled $enterpriseAdminEnabled -ErrorAction Stop
                        $needsUpdate = $true
                    }
                    
                    if ($existingUser.Description -ne $enterpriseAdminDescription) {
                        Write-Log "    Updating Description" -Level INFO
                        Set-ADUser -Identity $userName -Description $enterpriseAdminDescription -ErrorAction Stop
                        $needsUpdate = $true
                    }
                    
                    if ($needsUpdate) {
                        Write-LogChange -Object $userName -Attribute "Properties" -OldValue "Various" -NewValue "Updated to config"
                    }
                    
                    $enterpriseAdminUsers += $existingUser
                    Write-Log "    [+] User verified/updated: $userName" -Level SUCCESS
                }
                else {
                    # Create new user
                    Write-Log "  Creating new user: $userName" -Level INFO
                    
                    New-ADUser `
                        -Name $userName `
                        -SamAccountName $userName `
                        -AccountPassword $securePassword `
                        -Enabled $enterpriseAdminEnabled `
                        -Description $enterpriseAdminDescription `
                        -ChangePasswordAtLogon $false `
                        -ErrorAction Stop
                    
                    Write-LogChange -Object $userName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
                    Write-Log "    [+] User created: $userName" -Level SUCCESS
                    
                    # Wait for replication
                    Start-Sleep -Milliseconds 500
                    
                    # Retrieve the created user
                    $user = Get-ADUser -Identity $userName -ErrorAction Stop
                    $enterpriseAdminUsers += $user
                }
                
                $successCount++
            }
            catch {
                Write-Log "    [!] Error with $userName : $_" -Level ERROR
                $errorCount++
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 3: ADD USERS TO SCHEMA ADMINS GROUP
    ################################################################################
    
    Write-Log "PHASE 3: Adding Users to Schema Admins Group" -Level INFO
    Write-Log "" -Level INFO
    
    if ($schemaAdminUsers.Count -gt 0) {
        try {
            $schemaAdminsGroup = Get-ADGroup -Identity "Schema Admins" -ErrorAction Stop
            Write-Log "Found Schema Admins group" -Level INFO
            
            foreach ($user in $schemaAdminUsers) {
                try {
                    # Check if already a member (idempotent)
                    $isMember = Get-ADGroupMember -Identity $schemaAdminsGroup -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
                    
                    if ($isMember) {
                        Write-Log "  [*] $($user.Name) already in Schema Admins" -Level INFO
                    }
                    else {
                        Add-ADGroupMember -Identity $schemaAdminsGroup -Members $user -ErrorAction Stop
                        Write-LogChange -Object $user.Name -Attribute "Group Membership" -OldValue "N/A" -NewValue "Schema Admins"
                        Write-Log "  [+] Added to Schema Admins: $($user.Name)" -Level SUCCESS
                    }
                    
                    $successCount++
                }
                catch {
                    Write-Log "  [!] Error adding $($user.Name) to Schema Admins: $_" -Level ERROR
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error accessing Schema Admins group: $_" -Level ERROR
            $errorCount++
        }
    }
    else {
        Write-Log "  [*] No Schema Admin users to add" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 4: ADD USERS TO ENTERPRISE ADMINS GROUP
    ################################################################################
    
    Write-Log "PHASE 4: Adding Users to Enterprise Admins Group" -Level INFO
    Write-Log "" -Level INFO
    
    if ($enterpriseAdminUsers.Count -gt 0) {
        try {
            $enterpriseAdminsGroup = Get-ADGroup -Identity "Enterprise Admins" -ErrorAction Stop
            Write-Log "Found Enterprise Admins group" -Level INFO
            
            foreach ($user in $enterpriseAdminUsers) {
                try {
                    # Check if already a member (idempotent)
                    $isMember = Get-ADGroupMember -Identity $enterpriseAdminsGroup -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
                    
                    if ($isMember) {
                        Write-Log "  [*] $($user.Name) already in Enterprise Admins" -Level INFO
                    }
                    else {
                        Add-ADGroupMember -Identity $enterpriseAdminsGroup -Members $user -ErrorAction Stop
                        Write-LogChange -Object $user.Name -Attribute "Group Membership" -OldValue "N/A" -NewValue "Enterprise Admins"
                        Write-Log "  [+] Added to Enterprise Admins: $($user.Name)" -Level SUCCESS
                    }
                    
                    $successCount++
                }
                catch {
                    Write-Log "  [!] Error adding $($user.Name) to Enterprise Admins: $_" -Level ERROR
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error accessing Enterprise Admins group: $_" -Level ERROR
            $errorCount++
        }
    }
    else {
        Write-Log "  [*] No Enterprise Admin users to add" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 5: ENABLE PRINT SPOOLER ON DOMAIN CONTROLLERS
    ################################################################################
    
    Write-Log "PHASE 5: Enabling Print Spooler on Domain Controllers" -Level INFO
    Write-Log "" -Level INFO
    
    if ($config['InfrastructureSecurity_EnablePrintSpooler'] -eq 'true') {
        try {
            $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
            Write-Log "Found $($dcs.Count) Domain Controller(s)" -Level INFO
            
            foreach ($dcItem in $dcs) {
                try {
                    Write-Log "  Targeting: $($dcItem.HostName)" -Level INFO
                    
                    $spoolerService = Get-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
                    
                    $serviceUpdated = $false
                    
                    # Check and update startup type
                    if ($spoolerService.StartType -ne "Automatic") {
                        Set-Service -Name Spooler -ComputerName $dcItem.HostName -StartupType Automatic -ErrorAction Stop
                        Write-Log "    Updated StartupType: $($spoolerService.StartType) → Automatic" -Level INFO
                        $serviceUpdated = $true
                    }
                    
                    # Check and start service
                    if ($spoolerService.Status -ne "Running") {
                        Start-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
                        Write-Log "    Started Spooler service" -Level INFO
                        $serviceUpdated = $true
                    }
                    
                    if ($serviceUpdated) {
                        Write-LogChange -Object $dcItem.HostName -Attribute "Spooler" -OldValue "Stopped/Manual" -NewValue "Running/Automatic"
                        Write-Log "    [+] Print Spooler enabled" -Level SUCCESS
                    }
                    else {
                        Write-Log "    [*] Print Spooler already enabled" -Level INFO
                    }
                    
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error on $($dcItem.HostName): $_" -Level ERROR
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error enumerating Domain Controllers: $_" -Level ERROR
            $errorCount++
        }
    }
    else {
        Write-Log "  [*] Print Spooler configuration disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 6: MODIFY dSHEURISTICS
    ################################################################################
    
    Write-Log "PHASE 6: Modifying dSHeuristics" -Level INFO
    Write-Log "" -Level INFO
    
    if ($config['InfrastructureSecurity_ModifydSHeuristics'] -eq 'true') {
        try {
            # Build configuration naming context from domain DN
            # DC=d3,DC=lab -> CN=Configuration,DC=d3,DC=lab
            $domainDNParts = $domain.DistinguishedName -split ','
            $configNC = "CN=Configuration," + ($domainDNParts -join ',')
            $directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            
            Write-Log "Directory Service Path: $directoryServicePath" -Level INFO
            
            # Use LDAP to get and set dSHeuristics (more reliable)
            $ldapPath = "LDAP://$directoryServicePath"
            $directoryService = [ADSI]$ldapPath
            $currentdSH = $directoryService.dSHeuristics.Value
            
            Write-Log "  Current dSHeuristics: '$currentdSH'" -Level INFO
            
            # Enable anonymous NSPI (position 7 = 1)
            # This is a realistic misconfiguration that DSP detects
            $newdSH = "00000001"
            
            if ($newdSH -ne $currentdSH) {
                try {
                    $directoryService.Put("dSHeuristics", $newdSH)
                    $directoryService.SetInfo()
                    
                    Write-LogChange -Object "Directory Service" -Attribute "dSHeuristics" -OldValue $currentdSH -NewValue $newdSH
                    Write-Log "  [+] dSHeuristics modified: '$newdSH'" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error setting dSHeuristics: $_" -Level ERROR
                    $errorCount++
                }
            }
            else {
                Write-Log "  [*] dSHeuristics already at target value" -Level INFO
            }
        }
        catch {
            Write-Log "  [!] Error modifying dSHeuristics: $_" -Level ERROR
            $errorCount++
        }
    }
    else {
        Write-Log "  [*] dSHeuristics modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # SUMMARY
    ################################################################################
    
    Write-Log "========================================" -Level INFO
    Write-Log "Infrastructure Security Module Complete" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Successful operations: $successCount" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Errors encountered: $errorCount" -Level WARNING
        Write-Log "" -Level INFO
        return $false
    }
    
    Write-Log "" -Level INFO
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity