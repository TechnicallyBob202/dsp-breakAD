################################################################################
##
## dsp-BreakAD-Module-01-InfrastructureSecurity.psm1
##
## Infrastructure Security Misconfigurations
##
## Module 1 creates infrastructure-level security weaknesses:
## - Creates organizational unit structure
## - Creates dedicated bad user accounts (Schema Admin and Enterprise Admin users)
## - Adds users to privileged groups
## - Enables Print Spooler on all Domain Controllers
## - Modifies dSHeuristics for dangerous settings
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 3.0.0 - Single phase user creation
##
################################################################################

function Invoke-ModuleInfrastructureSecurity {
    <#
    .SYNOPSIS
        Applies infrastructure security misconfigurations
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 01: Infrastructure Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 0: CREATE ORGANIZATIONAL UNITS
    ################################################################################
    
    Write-Log "PHASE 0: Create Organizational Units" -Level INFO
    
    $domainDN = $domain.DistinguishedName
    $rootOUName = $config['BreakAD_RootOU']
    $usersOUName = $config['BreakAD_UsersOU']
    $computersOUName = $config['BreakAD_ComputersOU']
    
    $rootOUPath = "OU=$rootOUName,$domainDN"
    $usersOUPath = "OU=$usersOUName,OU=$rootOUName,$domainDN"
    $computersOUPath = "OU=$computersOUName,OU=$rootOUName,$domainDN"
    
    Write-Log "  Root OU: $rootOUPath" -Level INFO
    Write-Log "  Users OU: $usersOUPath" -Level INFO
    Write-Log "  Computers OU: $computersOUPath" -Level INFO
    
    # Create root OU if it doesn't exist
    $rootOUExists = Get-ADOrganizationalUnit -Filter "Name -eq '$rootOUName'" -ErrorAction SilentlyContinue
    if ($null -eq $rootOUExists) {
        Write-Log "  Creating root OU: $rootOUName" -Level INFO
        New-ADOrganizationalUnit -Name $rootOUName -Path $domainDN -ErrorAction Stop
        Write-LogChange -Object $rootOUName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
        Write-Log "    [+] Root OU created" -Level SUCCESS
    }
    else {
        Write-Log "  [*] Root OU already exists" -Level INFO
    }
    
    # Create users OU if it doesn't exist
    $usersOUExists = Get-ADOrganizationalUnit -Filter "Name -eq '$usersOUName'" -ErrorAction SilentlyContinue | 
        Where-Object { $_.DistinguishedName -eq $usersOUPath }
    if ($null -eq $usersOUExists) {
        Write-Log "  Creating users OU: $usersOUName" -Level INFO
        New-ADOrganizationalUnit -Name $usersOUName -Path $rootOUPath -ErrorAction Stop
        Write-LogChange -Object $usersOUName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
        Write-Log "    [+] Users OU created" -Level SUCCESS
    }
    else {
        Write-Log "  [*] Users OU already exists" -Level INFO
    }
    
    # Create computers OU if it doesn't exist
    $computersOUExists = Get-ADOrganizationalUnit -Filter "Name -eq '$computersOUName'" -ErrorAction SilentlyContinue | 
        Where-Object { $_.DistinguishedName -eq $computersOUPath }
    if ($null -eq $computersOUExists) {
        Write-Log "  Creating computers OU: $computersOUName" -Level INFO
        New-ADOrganizationalUnit -Name $computersOUName -Path $rootOUPath -ErrorAction Stop
        Write-LogChange -Object $computersOUName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
        Write-Log "    [+] Computers OU created" -Level SUCCESS
    }
    else {
        Write-Log "  [*] Computers OU already exists" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 1: VALIDATE CONFIG & SETUP
    ################################################################################
    
    Write-Log "PHASE 1: Validate Config & Setup" -Level INFO
    
    $schemaAdminCount = [int]$config['InfrastructureSecurity_SchemaAdminCount']
    $schemaAdminPassword = $config['InfrastructureSecurity_SchemaAdminPassword']
    $schemaAdminEnabled = $config['InfrastructureSecurity_SchemaAdminEnabled'] -eq 'true'
    $schemaAdminDescription = $config['InfrastructureSecurity_SchemaAdminDescription']
    
    $enterpriseAdminCount = [int]$config['InfrastructureSecurity_EnterpriseAdminCount']
    $enterpriseAdminPassword = $config['InfrastructureSecurity_EnterpriseAdminPassword']
    $enterpriseAdminEnabled = $config['InfrastructureSecurity_EnterpriseAdminEnabled'] -eq 'true'
    $enterpriseAdminDescription = $config['InfrastructureSecurity_EnterpriseAdminDescription']
    
    Write-Log "  Schema Admin count: $schemaAdminCount" -Level INFO
    Write-Log "  Enterprise Admin count: $enterpriseAdminCount" -Level INFO
    Write-Log "  Print Spooler: $($config['InfrastructureSecurity_EnablePrintSpooler'])" -Level INFO
    Write-Log "  dSHeuristics: $($config['InfrastructureSecurity_ModifydSHeuristics'])" -Level INFO
    
    # Validate passwords are not empty
    if ([string]::IsNullOrEmpty($schemaAdminPassword)) {
        Write-Log "[!] ERROR: Schema Admin password is empty in config" -Level ERROR
        return $false
    }
    
    if ([string]::IsNullOrEmpty($enterpriseAdminPassword)) {
        Write-Log "[!] ERROR: Enterprise Admin password is empty in config" -Level ERROR
        return $false
    }
    
    # Create secure password objects
    $schemaAdminSecurePassword = ConvertTo-SecureString $schemaAdminPassword -AsPlainText -Force
    $enterpriseAdminSecurePassword = ConvertTo-SecureString $enterpriseAdminPassword -AsPlainText -Force
    
    Write-Log "[+] Config validated" -Level SUCCESS
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 2: CREATE ALL USERS
    ################################################################################
    
    Write-Log "PHASE 2: Create All Users" -Level INFO
    
    $schemaAdminUsers = @()
    $enterpriseAdminUsers = @()
    
    # Create Schema Admin users
    if ($schemaAdminCount -gt 0) {
        Write-Log "  Creating $schemaAdminCount Schema Admin user(s)..." -Level INFO
        
        for ($i = 1; $i -le $schemaAdminCount; $i++) {
            $userName = "break-SchemaAdmin-" + "{0:D2}" -f $i
            
            Write-Log "    Processing: $userName" -Level INFO
            
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction SilentlyContinue
            
            if ($null -ne $existingUser) {
                Write-Log "      [*] User already exists" -Level INFO
                $schemaAdminUsers += $existingUser
            }
            else {
                Write-Log "      Creating..." -Level INFO
                
                # Create the user
                New-ADUser `
                    -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $schemaAdminSecurePassword `
                    -Enabled $schemaAdminEnabled `
                    -Description $schemaAdminDescription `
                    -ChangePasswordAtLogon $false `
                    -Path $usersOUPath `
                    -ErrorAction Stop
                
                Write-LogChange -Object $userName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
                Write-Log "      [+] Created" -Level SUCCESS
                
                # Wait for AD to process
                Start-Sleep -Seconds 2
                
                # Retrieve the user
                $newUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction Stop
                if ($null -eq $newUser) {
                    Write-Log "      [!] ERROR: Could not retrieve user after creation" -Level ERROR
                    return $false
                }
                
                $schemaAdminUsers += $newUser
                Write-Log "      [+] Retrieved" -Level SUCCESS
            }
        }
    }
    
    # Create Enterprise Admin users
    if ($enterpriseAdminCount -gt 0) {
        Write-Log "  Creating $enterpriseAdminCount Enterprise Admin user(s)..." -Level INFO
        
        for ($i = 1; $i -le $enterpriseAdminCount; $i++) {
            $userName = "break-EntAdmin-" + "{0:D2}" -f $i
            
            Write-Log "    Processing: $userName" -Level INFO
            
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction SilentlyContinue
            
            if ($null -ne $existingUser) {
                Write-Log "      [*] User already exists" -Level INFO
                $enterpriseAdminUsers += $existingUser
            }
            else {
                Write-Log "      Creating..." -Level INFO
                
                # DEBUG: Check password object
                if ($null -eq $enterpriseAdminSecurePassword) {
                    Write-Log "      [!] ERROR: enterpriseAdminSecurePassword is NULL!" -Level ERROR
                    return $false
                }
                Write-Log "      [DEBUG] Password type: $($enterpriseAdminSecurePassword.GetType().Name)" -Level INFO
                
                # Create the user
                New-ADUser `
                    -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $enterpriseAdminSecurePassword `
                    -Enabled $enterpriseAdminEnabled `
                    -Description "Test Description" `
                    -ChangePasswordAtLogon $false `
                    -Path $usersOUPath `
                    -ErrorAction Stop
                
                Write-LogChange -Object $userName -Attribute "Creation" -OldValue "N/A" -NewValue "Created"
                Write-Log "      [+] Created" -Level SUCCESS
                
                # Wait for AD to process
                Start-Sleep -Seconds 2
                
                # Retrieve the user
                $newUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction Stop
                if ($null -eq $newUser) {
                    Write-Log "      [!] ERROR: Could not retrieve user after creation" -Level ERROR
                    return $false
                }
                
                $enterpriseAdminUsers += $newUser
                Write-Log "      [+] Retrieved" -Level SUCCESS
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 3: ADD SCHEMA ADMIN USERS TO GROUP
    ################################################################################
    
    Write-Log "PHASE 3: Add Schema Admin Users to Schema Admins Group" -Level INFO
    
    if ($schemaAdminUsers.Count -gt 0) {
        $schemaAdminsGroup = Get-ADGroup -Identity "Schema Admins" -ErrorAction Stop
        
        foreach ($user in $schemaAdminUsers) {
            Write-Log "  Adding: $($user.Name)" -Level INFO
            
            # Check if already a member
            $isMember = Get-ADGroupMember -Identity $schemaAdminsGroup -ErrorAction SilentlyContinue | 
                Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
            
            if ($null -ne $isMember) {
                Write-Log "    [*] Already member" -Level INFO
            }
            else {
                Add-ADGroupMember -Identity $schemaAdminsGroup -Members $user -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "Group" -OldValue "N/A" -NewValue "Schema Admins"
                Write-Log "    [+] Added to Schema Admins" -Level SUCCESS
            }
        }
    }
    else {
        Write-Log "  [*] No Schema Admin users to add" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 4: ADD ENTERPRISE ADMIN USERS TO GROUP
    ################################################################################
    
    Write-Log "PHASE 4: Add Enterprise Admin Users to Enterprise Admins Group" -Level INFO
    
    if ($enterpriseAdminUsers.Count -gt 0) {
        $enterpriseAdminsGroup = Get-ADGroup -Identity "Enterprise Admins" -ErrorAction Stop
        
        foreach ($user in $enterpriseAdminUsers) {
            Write-Log "  Adding: $($user.Name)" -Level INFO
            
            # Check if already a member
            $isMember = Get-ADGroupMember -Identity $enterpriseAdminsGroup -ErrorAction SilentlyContinue | 
                Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
            
            if ($null -ne $isMember) {
                Write-Log "    [*] Already member" -Level INFO
            }
            else {
                Add-ADGroupMember -Identity $enterpriseAdminsGroup -Members $user -ErrorAction Stop
                Write-LogChange -Object $user.Name -Attribute "Group" -OldValue "N/A" -NewValue "Enterprise Admins"
                Write-Log "    [+] Added to Enterprise Admins" -Level SUCCESS
            }
        }
    }
    else {
        Write-Log "  [*] No Enterprise Admin users to add" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 5: ENABLE PRINT SPOOLER ON DCS
    ################################################################################
    
    Write-Log "PHASE 5: Enable Print Spooler on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_EnablePrintSpooler'] -eq 'true') {
        $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
        
        foreach ($dcItem in $dcs) {
            Write-Log "  Processing DC: $($dcItem.HostName)" -Level INFO
            
            $spoolerService = Get-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
            
            # Check startup type
            if ($spoolerService.StartType -ne "Automatic") {
                Set-Service -Name Spooler -ComputerName $dcItem.HostName -StartupType Automatic -ErrorAction Stop
                Write-Log "    Set StartupType to Automatic" -Level INFO
            }
            
            # Check service status
            if ($spoolerService.Status -ne "Running") {
                Start-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
                Write-Log "    Started service" -Level INFO
            }
            
            Write-LogChange -Object $dcItem.HostName -Attribute "Spooler" -OldValue "Stopped/Manual" -NewValue "Running/Automatic"
            Write-Log "    [+] Print Spooler enabled" -Level SUCCESS
        }
    }
    else {
        Write-Log "  [*] Print Spooler configuration disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 6: MODIFY dSHEURISTICS
    ################################################################################
    
    Write-Log "PHASE 6: Modify dSHeuristics" -Level INFO
    
    if ($config['InfrastructureSecurity_ModifydSHeuristics'] -eq 'true') {
        # Build configuration naming context from domain DN
        $domainDNParts = $domain.DistinguishedName -split ','
        $configNC = "CN=Configuration," + ($domainDNParts -join ',')
        $directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
        
        Write-Log "  Directory Service Path: $directoryServicePath" -Level INFO
        
        # Connect via LDAP
        $ldapPath = "LDAP://$directoryServicePath"
        $directoryService = [ADSI]$ldapPath
        
        $currentdSH = $directoryService.dSHeuristics.Value
        Write-Log "  Current value: '$currentdSH'" -Level INFO
        
        $targetdSH = "00000001"
        
        if ($currentdSH -ne $targetdSH) {
            $directoryService.Put("dSHeuristics", $targetdSH)
            $directoryService.SetInfo()
            
            Write-LogChange -Object "Directory Service" -Attribute "dSHeuristics" -OldValue $currentdSH -NewValue $targetdSH
            Write-Log "  [+] dSHeuristics modified to: '$targetdSH'" -Level SUCCESS
        }
        else {
            Write-Log "  [*] Already at target value" -Level INFO
        }
    }
    else {
        Write-Log "  [*] dSHeuristics modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # COMPLETION
    ################################################################################
    
    Write-Log "========================================" -Level INFO
    Write-Log "Module 01: Infrastructure Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Status: COMPLETE" -Level SUCCESS
    Write-Log "" -Level INFO
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity