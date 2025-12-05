################################################################################
##
## dsp-BreakAD-Module-01-InfrastructureSecurity.psm1 (ENHANCED)
##
## Infrastructure Security Misconfigurations
##
## Module 1 creates infrastructure-level security weaknesses:
## - Creates organizational unit structure
## - Creates dedicated bad user accounts (Schema Admin and Enterprise Admin users)
## - Adds users to privileged groups
## - Adds users to risky operator groups
## - Adds users to Distributed COM Users and Performance Log Users
## - Enables Print Spooler on all Domain Controllers
## - Modifies dSHeuristics for dangerous settings
## - Configures weak encryption (DES) on accounts
## - Disables Kerberos pre-auth on admin accounts
## - Enables reversible encryption on accounts
## - Creates disabled privileged user accounts
## - Adds computer accounts to privileged groups
## - Sets weak adminCount values
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 4.0.0 - Enhanced with IOE triggers
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
    $usersOUPath = "OU=$usersOUName,$rootOUPath"
    $computersOUPath = "OU=$computersOUName,$rootOUPath"
    
    # Create root OU
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$rootOUName'" -SearchBase $domainDN -ErrorAction SilentlyContinue)) {
        Write-Log "  Creating root OU: $rootOUName" -Level INFO
        New-ADOrganizationalUnit -Name $rootOUName -Path $domainDN -ErrorAction Stop
        Write-Log "    [+] OU created" -Level SUCCESS
    }
    else {
        Write-Log "  [*] Root OU already exists" -Level INFO
    }
    
    # Create users OU
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$usersOUName'" -SearchBase $rootOUPath -ErrorAction SilentlyContinue)) {
        Write-Log "  Creating users OU: $usersOUName" -Level INFO
        New-ADOrganizationalUnit -Name $usersOUName -Path $rootOUPath -ErrorAction Stop
        Write-Log "    [+] OU created" -Level SUCCESS
    }
    else {
        Write-Log "  [*] Users OU already exists" -Level INFO
    }
    
    # Create computers OU
    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$computersOUName'" -SearchBase $rootOUPath -ErrorAction SilentlyContinue)) {
        Write-Log "  Creating computers OU: $computersOUName" -Level INFO
        New-ADOrganizationalUnit -Name $computersOUName -Path $rootOUPath -ErrorAction Stop
        Write-Log "    [+] OU created" -Level SUCCESS
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
    $allCreatedUsers = @()
    
    # Create Schema Admin users
    if ($schemaAdminCount -gt 0) {
        Write-Log "  Creating $schemaAdminCount Schema Admin user(s)..." -Level INFO
        
        for ($i = 1; $i -le $schemaAdminCount; $i++) {
            $userName = "break-schema-adm-" + "{0:D2}" -f $i
            
            Write-Log "    Processing: $userName" -Level INFO
            
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction SilentlyContinue
            
            if ($null -ne $existingUser) {
                Write-Log "      [+] User already exists" -Level SUCCESS
                $schemaAdminUsers += $existingUser
                $allCreatedUsers += $existingUser
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
                
                Write-Log "      [+] Created" -Level SUCCESS
                
                # Wait for AD to process
                Start-Sleep -Seconds 1
                
                # Retrieve the user
                $newUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction Stop
                if ($null -eq $newUser) {
                    Write-Log "      [!] ERROR: Could not retrieve user after creation" -Level ERROR
                    return $false
                }
                
                $schemaAdminUsers += $newUser
                $allCreatedUsers += $newUser
                Write-Log "      [+] Retrieved" -Level SUCCESS
            }
        }
    }
    
    # Create Enterprise Admin users
    if ($enterpriseAdminCount -gt 0) {
        Write-Log "  Creating $enterpriseAdminCount Enterprise Admin user(s)..." -Level INFO
        
        for ($i = 1; $i -le $enterpriseAdminCount; $i++) {
            $userName = "break-ent-adm-" + "{0:D2}" -f $i
            
            Write-Log "    Processing: $userName" -Level INFO
            
            # Check if user already exists
            $existingUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction SilentlyContinue
            
            if ($null -ne $existingUser) {
                Write-Log "      [+] User already exists" -Level SUCCESS
                $enterpriseAdminUsers += $existingUser
                $allCreatedUsers += $existingUser
            }
            else {
                Write-Log "      Creating..." -Level INFO
                
                New-ADUser `
                    -Name $userName `
                    -SamAccountName $userName `
                    -AccountPassword $enterpriseAdminSecurePassword `
                    -Enabled $enterpriseAdminEnabled `
                    -Description $enterpriseAdminDescription `
                    -ChangePasswordAtLogon $false `
                    -Path $usersOUPath `
                    -ErrorAction Stop
                
                Write-Log "      [+] Created" -Level SUCCESS
                
                # Wait for AD to process
                Start-Sleep -Seconds 1
                
                # Retrieve the user
                $newUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -SearchBase $usersOUPath -ErrorAction Stop
                if ($null -eq $newUser) {
                    Write-Log "      [!] ERROR: Could not retrieve user after creation" -Level ERROR
                    return $false
                }
                
                $enterpriseAdminUsers += $newUser
                $allCreatedUsers += $newUser
                Write-Log "      [+] Retrieved" -Level SUCCESS
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 3: ADD TO PRIVILEGED GROUPS
    ################################################################################
    
    Write-Log "PHASE 3: Add Users to Privileged Groups" -Level INFO
    
    # Add Schema Admin users to Schema Admins group
    if ($schemaAdminUsers.Count -gt 0) {
        Write-Log "  Adding to Schema Admins group..." -Level INFO
        $schemaAdminsGroup = Get-ADGroup -Identity "Schema Admins" -ErrorAction Stop
        
        foreach ($user in $schemaAdminUsers) {
            Write-Log "    Adding: $($user.Name)" -Level INFO
            
            # Check if already a member
            $isMember = Get-ADGroupMember -Identity $schemaAdminsGroup -ErrorAction SilentlyContinue | 
                Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
            
            if ($null -ne $isMember) {
                Write-Log "      [+] Already member" -Level SUCCESS
            }
            else {
                Add-ADGroupMember -Identity $schemaAdminsGroup -Members $user -ErrorAction Stop
                Write-Log "      [+] Added to Schema Admins" -Level SUCCESS
            }
        }
    }
    
    # Add Enterprise Admin users to Enterprise Admins group
    if ($enterpriseAdminUsers.Count -gt 0) {
        Write-Log "  Adding to Enterprise Admins group..." -Level INFO
        $enterpriseAdminsGroup = Get-ADGroup -Identity "Enterprise Admins" -ErrorAction Stop
        
        foreach ($user in $enterpriseAdminUsers) {
            Write-Log "    Adding: $($user.Name)" -Level INFO
            
            # Check if already a member
            $isMember = Get-ADGroupMember -Identity $enterpriseAdminsGroup -ErrorAction SilentlyContinue | 
                Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
            
            if ($null -ne $isMember) {
                Write-Log "      [+] Already member" -Level SUCCESS
            }
            else {
                Add-ADGroupMember -Identity $enterpriseAdminsGroup -Members $user -ErrorAction Stop
                Write-Log "      [+] Added to Enterprise Admins" -Level SUCCESS
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 4: ADD TO RISKY OPERATOR GROUPS
    ################################################################################
    
    Write-Log "PHASE 4: Add Users to Operator Groups" -Level INFO
    
    if ($allCreatedUsers.Count -gt 0) {
        $operatorGroups = @("Backup Operators", "Print Operators", "Account Operators")
        
        foreach ($groupName in $operatorGroups) {
            Write-Log "  Adding to $groupName..." -Level INFO
            
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            
            if ($null -ne $group) {
                # Add first user to this group
                $user = $allCreatedUsers[0]
                Write-Log "    Adding: $($user.Name)" -Level INFO
                
                $isMember = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
                
                if ($null -ne $isMember) {
                    Write-Log "      [+] Already member" -Level SUCCESS
                }
                else {
                    Add-ADGroupMember -Identity $group -Members $user -ErrorAction SilentlyContinue
                    Write-Log "      [+] Added to $groupName" -Level SUCCESS
                }
            }
            else {
                Write-Log "  [!] Group not found: $groupName" -Level WARNING
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 5: ADD TO DISTRIBUTED COM USERS AND PERFORMANCE LOG USERS
    ################################################################################
    
    Write-Log "PHASE 5: Add to Distributed COM and Performance Log Groups" -Level INFO
    
    if ($allCreatedUsers.Count -gt 0) {
        $specialGroups = @("Distributed COM Users", "Performance Log Users")
        
        foreach ($groupName in $specialGroups) {
            Write-Log "  Adding to $groupName..." -Level INFO
            
            $group = Get-ADGroup -Filter "Name -eq '$groupName'" -ErrorAction SilentlyContinue
            
            if ($null -ne $group) {
                # Add first user to this group
                $user = $allCreatedUsers[0]
                Write-Log "    Adding: $($user.Name)" -Level INFO
                
                $isMember = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DistinguishedName -eq $user.DistinguishedName }
                
                if ($null -ne $isMember) {
                    Write-Log "      [+] Already member" -Level SUCCESS
                }
                else {
                    Add-ADGroupMember -Identity $group -Members $user -ErrorAction SilentlyContinue
                    Write-Log "      [+] Added to $groupName" -Level SUCCESS
                }
            }
            else {
                Write-Log "  [!] Group not found: $groupName" -Level WARNING
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 6: CONFIGURE ACCOUNT PROPERTIES - DES ENCRYPTION
    ################################################################################
    
    Write-Log "PHASE 6: Configure DES Encryption on Accounts" -Level INFO
    
    if ($schemaAdminUsers.Count -gt 0 -and $schemaAdminUsers[0]) {
        Write-Log "  Setting DES encryption on: $($schemaAdminUsers[0].Name)" -Level INFO
        
        try {
            # Set-ADUser doesn't support KerberosEncryptionType directly, use Set-ADAccountControl
            Set-ADUser -Identity $schemaAdminUsers[0] `
                -Replace @{"msDS-SupportedEncryptionTypes" = 1} `
                -ErrorAction Stop
            
            Write-Log "    [+] DES encryption configured" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error setting DES encryption: $_" -Level WARNING
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 7: DISABLE KERBEROS PRE-AUTH ON ADMIN ACCOUNTS
    ################################################################################
    
    Write-Log "PHASE 7: Disable Kerberos Pre-Auth on Admin Accounts" -Level INFO
    
    if ($enterpriseAdminUsers.Count -gt 0 -and $enterpriseAdminUsers[0]) {
        Write-Log "  Disabling pre-auth on: $($enterpriseAdminUsers[0].Name)" -Level INFO
        
        try {
            Set-ADUser -Identity $enterpriseAdminUsers[0] `
                -Replace @{"userAccountControl" = 4194816} `
                -ErrorAction Stop
            
            Write-Log "    [+] Pre-auth disabled (AS-REP roasting vector)" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error disabling pre-auth: $_" -Level WARNING
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 8: ENABLE REVERSIBLE ENCRYPTION
    ################################################################################
    
    Write-Log "PHASE 8: Enable Reversible Encryption on Accounts" -Level INFO
    
    if ($allCreatedUsers.Count -gt 0 -and $allCreatedUsers[0]) {
        Write-Log "  Enabling reversible encryption on: $($allCreatedUsers[0].Name)" -Level INFO
        
        try {
            # Set userAccountControl flag for reversible encryption (128)
            $user = Get-ADUser -Identity $allCreatedUsers[0]
            $uac = $user.userAccountControl
            $uac = $uac -bor 128
            
            Set-ADUser -Identity $user -Replace @{"userAccountControl" = $uac} -ErrorAction Stop
            
            Write-Log "    [+] Reversible encryption enabled" -Level SUCCESS
        }
        catch {
            Write-Log "    [!] Error enabling reversible encryption: $_" -Level WARNING
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 9: CREATE DISABLED PRIVILEGED ACCOUNT
    ################################################################################
    
    Write-Log "PHASE 9: Create Disabled Privileged Account" -Level INFO
    
    $disabledAdminName = "break-disabled-adm"
    
    # Check if already exists
    $existingDisabledAdmin = Get-ADUser -Filter "SamAccountName -eq '$disabledAdminName'" -SearchBase $usersOUPath -ErrorAction SilentlyContinue
    
    if ($null -eq $existingDisabledAdmin) {
        Write-Log "  Creating disabled privileged account..." -Level INFO
        
        $tempPassword = ConvertTo-SecureString "DisabledAdm!n123" -AsPlainText -Force
        
        try {
            New-ADUser `
                -Name $disabledAdminName `
                -SamAccountName $disabledAdminName `
                -AccountPassword $tempPassword `
                -Enabled $false `
                -Description "Disabled privileged account for testing" `
                -ChangePasswordAtLogon $false `
                -Path $usersOUPath `
                -ErrorAction Stop
            
            Write-Log "    [+] Created and disabled" -Level SUCCESS
            
            # Add to Domain Admins while disabled
            Start-Sleep -Seconds 1
            $disabledAdmin = Get-ADUser -Filter "SamAccountName -eq '$disabledAdminName'" -SearchBase $usersOUPath -ErrorAction Stop
            
            if ($null -ne $disabledAdmin) {
                $domainAdminsGroup = Get-ADGroup -Identity "Domain Admins" -ErrorAction Stop
                Add-ADGroupMember -Identity $domainAdminsGroup -Members $disabledAdmin -ErrorAction SilentlyContinue
                Write-Log "    [+] Added to Domain Admins (while disabled)" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error creating disabled admin: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Disabled admin account already exists" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 10: ADD COMPUTER ACCOUNTS TO PRIVILEGED GROUPS
    ################################################################################
    
    Write-Log "PHASE 10: Add Computer Accounts to Privileged Groups" -Level INFO
    
    # Create a test computer account
    $computerName = "break-computer"
    
    $existingComputer = Get-ADComputer -Filter "Name -eq '$computerName'" -SearchBase $computersOUPath -ErrorAction SilentlyContinue
    
    if ($null -eq $existingComputer) {
        Write-Log "  Creating computer account: $computerName" -Level INFO
        
        try {
            New-ADComputer `
                -Name $computerName `
                -SamAccountName $computerName `
                -Path $computersOUPath `
                -Enabled $true `
                -ErrorAction Stop
            
            Write-Log "    [+] Created" -Level SUCCESS
            
            # Wait for AD to process
            Start-Sleep -Seconds 2
            
            $computer = Get-ADComputer -Filter "Name -eq '$computerName'" -SearchBase $computersOUPath -ErrorAction Stop
            
            if ($null -ne $computer) {
                # Add to Domain Admins
                $domainAdminsGroup = Get-ADGroup -Identity "Domain Admins" -ErrorAction Stop
                Add-ADGroupMember -Identity $domainAdminsGroup -Members $computer -ErrorAction SilentlyContinue
                Write-Log "    [+] Added computer to Domain Admins" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error creating computer account: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Computer account already exists" -Level INFO
        
        # Ensure it's in Domain Admins
        $domainAdminsGroup = Get-ADGroup -Identity "Domain Admins" -ErrorAction SilentlyContinue
        if ($domainAdminsGroup) {
            $isMember = Get-ADGroupMember -Identity $domainAdminsGroup -ErrorAction SilentlyContinue | 
                Where-Object { $_.DistinguishedName -eq $existingComputer.DistinguishedName }
            
            if ($null -eq $isMember) {
                Add-ADGroupMember -Identity $domainAdminsGroup -Members $existingComputer -ErrorAction SilentlyContinue
                Write-Log "    [+] Added to Domain Admins" -Level SUCCESS
            }
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 11: ENABLE PRINT SPOOLER ON DCS
    ################################################################################
    
    Write-Log "PHASE 11: Enable Print Spooler on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_EnablePrintSpooler'] -eq 'true') {
        Write-Log "  Enabling Print Spooler..." -Level INFO
        
        try {
            # Get all Domain Controllers
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dc in $domainControllers) {
                Write-Log "    Processing DC: $($dc.HostName)" -Level INFO
                
                try {
                    # Enable and start Spooler service on DC
                    $spoolerService = Get-Service -Name Spooler -ComputerName $dc.HostName -ErrorAction SilentlyContinue
                    
                    if ($null -ne $spoolerService) {
                        if ($spoolerService.StartType -ne "Automatic") {
                            Set-Service -Name Spooler -StartupType Automatic -ComputerName $dc.HostName -ErrorAction Stop
                            Write-Log "      [+] Startup type set to Automatic" -Level SUCCESS
                        }
                        
                        if ($spoolerService.Status -ne "Running") {
                            Start-Service -Name Spooler -ComputerName $dc.HostName -ErrorAction Stop
                            Write-Log "      [+] Service started" -Level SUCCESS
                        }
                        else {
                            Write-Log "      [+] Service already running" -Level SUCCESS
                        }
                    }
                    else {
                        Write-Log "      [!] Could not access Spooler service" -Level WARNING
                    }
                }
                catch {
                    Write-Log "      [!] Error enabling Spooler: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error accessing Domain Controllers: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Print Spooler modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 12: MODIFY dSHEURISTICS
    ################################################################################
    
    Write-Log "PHASE 12: Modify dSHeuristics" -Level INFO
    
    if ($config['InfrastructureSecurity_ModifydSHeuristics'] -eq 'true') {
        Write-Log "  Modifying dSHeuristics for dangerous settings..." -Level INFO
        
        try {
            # Get Config NC properly by querying RootDSE
            $rootDSE = Get-ADRootDSE
            $configNC = $rootDSE.configurationNamingContext
            $directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            
            Write-Log "    Directory Service Path: $directoryServicePath" -Level INFO
            
            # Connect via LDAP using ADSI
            $ldapPath = "LDAP://$directoryServicePath"
            $directoryService = [ADSI]$ldapPath
            
            $currentdSH = $directoryService.dSHeuristics.Value
            Write-Log "    Current value: '$currentdSH'" -Level INFO
            
            # Use value "00000001" which enables anonymous NSPI
            $targetdSH = "00000001"
            
            if ($currentdSH -ne $targetdSH) {
                $directoryService.Put("dSHeuristics", $targetdSH)
                $directoryService.SetInfo()
                
                Write-Log "    [+] dSHeuristics modified to: '$targetdSH'" -Level SUCCESS
            }
            else {
                Write-Log "    [+] Already at target value" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error modifying dSHeuristics: $_" -Level WARNING
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