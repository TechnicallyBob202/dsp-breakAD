################################################################################
##
## dsp-BreakAD-Module-01-InfrastructureSecurity.psm1 (REBUILT)
##
## Infrastructure Security Misconfigurations - Targeting AD Infrastructure IOEs
##
## Phases:
## 1: Enable dSHeuristics (Anonymous NSPI access)
## 2: Enable Print Spooler on DCs
## 3: Disable LDAP Signing on DCs (via GPO)
## 4: Disable SMB Signing on DCs (via GPO)
## 5: Enable SMBv1 on DCs (via GPO)
## 6: Add Anonymous to Pre-Windows 2000 Compatible Access
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 5.0.0 - Infrastructure IOEs rebuild with GPO
##
################################################################################

function Invoke-ModuleInfrastructureSecurity {
    <#
    .SYNOPSIS
        Applies infrastructure security misconfigurations targeting DSP IOEs
    
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
    # PHASE 1: ENABLE dSHEURISTICS (ANONYMOUS NSPI)
    ################################################################################
    
    Write-Log "PHASE 1: Enable dSHeuristics (Anonymous NSPI Access)" -Level INFO
    
    if ($config['InfrastructureSecurity_EnabledSHeuristics'] -eq 'true') {
        Write-Log "  Modifying dSHeuristics..." -Level INFO
        
        try {
            $rootDSE = Get-ADRootDSE
            $configNC = $rootDSE.configurationNamingContext
            $directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            
            $ldapPath = "LDAP://$directoryServicePath"
            $directoryService = [ADSI]$ldapPath
            
            $currentdSH = $directoryService.dSHeuristics.Value
            Write-Log "    Current value: '$currentdSH'" -Level INFO
            
            $targetdSH = $config['InfrastructureSecurity_dSHeuristicsValue']
            if ([string]::IsNullOrEmpty($targetdSH)) {
                $targetdSH = "00000001"
            }
            
            if ($currentdSH -ne $targetdSH) {
                $directoryService.Put("dSHeuristics", $targetdSH)
                $directoryService.SetInfo()
                Write-Log "    [+] dSHeuristics set to: '$targetdSH'" -Level SUCCESS
            }
            else {
                Write-Log "    [+] Already at target value" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] dSHeuristics modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 2: ENABLE PRINT SPOOLER ON DCS
    ################################################################################
    
    Write-Log "PHASE 2: Enable Print Spooler on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_EnablePrintSpooler'] -eq 'true') {
        Write-Log "  Enabling Print Spooler service..." -Level INFO
        
        try {
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dcItem in $domainControllers) {
                Write-Log "    Processing DC: $($dcItem.HostName)" -Level INFO
                
                try {
                    $spoolerService = Get-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction SilentlyContinue
                    
                    if ($null -ne $spoolerService) {
                        if ($spoolerService.StartType -ne "Automatic") {
                            Set-Service -Name Spooler -StartupType Automatic -ComputerName $dcItem.HostName -ErrorAction Stop
                            Write-Log "      [+] Startup type set to Automatic" -Level SUCCESS
                        }
                        
                        if ($spoolerService.Status -ne "Running") {
                            Start-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
                            Write-Log "      [+] Service started" -Level SUCCESS
                        }
                        else {
                            Write-Log "      [+] Service already running" -Level SUCCESS
                        }
                    }
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
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
    # PHASE 3: DISABLE LDAP SIGNING VIA GPO
    ################################################################################
    
    Write-Log "PHASE 3: Disable LDAP Signing on Domain Controllers via GPO" -Level INFO
    
    if ($config['InfrastructureSecurity_DisableLDAPSigning'] -eq 'true') {
        Write-Log "  Creating/modifying GPO for LDAP Signing..." -Level INFO
        
        try {
            $gpoName = "dsp-breakAD-LDAP-Signing"
            $dcOU = "OU=Domain Controllers,$($domain.DistinguishedName)"
            
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            
            if (-not $gpo) {
                Write-Log "    Creating new GPO: $gpoName" -Level INFO
                $gpo = New-GPO -Name $gpoName -Comment "dsp-breakAD: Disable LDAP Signing" -ErrorAction Stop
                Write-Log "      [+] GPO created" -Level SUCCESS
            }
            else {
                Write-Log "    [*] GPO already exists" -Level INFO
            }
            
            try {
                New-GPLink -Name $gpoName -Target $dcOU -ErrorAction Stop | Out-Null
                Write-Log "      [+] GPO linked to Domain Controllers OU" -Level SUCCESS
            }
            catch {
                Write-Log "      [*] GPO link already exists" -Level INFO
            }
            
            Set-GPPrefRegistryValue -Name $gpoName -Context Computer -Action Update -Key "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" -ValueName "LDAPServerIntegrity" -Value 0 -Type DWORD -ErrorAction Stop | Out-Null
            Write-Log "      [+] Registry preference set (LDAPServerIntegrity = 0)" -Level SUCCESS
            
            Write-Log "    Refreshing Group Policy on Domain Controllers..." -Level INFO
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            foreach ($dcItem in $domainControllers) {
                try {
                    Invoke-Command -ComputerName $dcItem.HostName -ScriptBlock { gpupdate /force /wait:0 } -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "      [+] GPO refresh initiated on $($dcItem.HostName)" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error refreshing GPO on $($dcItem.HostName): $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] LDAP Signing modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 4: DISABLE SMB SIGNING VIA GPO
    ################################################################################
    
    Write-Log "PHASE 4: Disable SMB Signing on Domain Controllers via GPO" -Level INFO
    
    if ($config['InfrastructureSecurity_DisableSMBSigning'] -eq 'true') {
        Write-Log "  Creating/modifying GPO for SMB Signing..." -Level INFO
        
        try {
            $gpoName = "dsp-breakAD-SMB-Signing"
            $dcOU = "OU=Domain Controllers,$($domain.DistinguishedName)"
            
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            
            if (-not $gpo) {
                Write-Log "    Creating new GPO: $gpoName" -Level INFO
                $gpo = New-GPO -Name $gpoName -Comment "dsp-breakAD: Disable SMB Signing" -ErrorAction Stop
                Write-Log "      [+] GPO created" -Level SUCCESS
            }
            else {
                Write-Log "    [*] GPO already exists" -Level INFO
            }
            
            try {
                New-GPLink -Name $gpoName -Target $dcOU -ErrorAction Stop | Out-Null
                Write-Log "      [+] GPO linked to Domain Controllers OU" -Level SUCCESS
            }
            catch {
                Write-Log "      [*] GPO link already exists" -Level INFO
            }
            
            Set-GPPrefRegistryValue -Name $gpoName -Context Computer -Action Update -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "RequireSecuritySignature" -Value 0 -Type DWORD -ErrorAction Stop | Out-Null
            Write-Log "      [+] Registry preference set (RequireSecuritySignature = 0)" -Level SUCCESS
            
            Write-Log "    Refreshing Group Policy on Domain Controllers..." -Level INFO
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            foreach ($dcItem in $domainControllers) {
                try {
                    Invoke-Command -ComputerName $dcItem.HostName -ScriptBlock { gpupdate /force /wait:0 } -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "      [+] GPO refresh initiated on $($dcItem.HostName)" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error refreshing GPO on $($dcItem.HostName): $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] SMB Signing modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 5: ENABLE SMBv1 VIA GPO
    ################################################################################
    
    Write-Log "PHASE 5: Enable SMBv1 on Domain Controllers via GPO" -Level INFO
    
    if ($config['InfrastructureSecurity_EnableSMBv1'] -eq 'true') {
        Write-Log "  Creating/modifying GPO for SMBv1..." -Level INFO
        Write-Log "  NOTE: SMBv1 may require Domain Controller restart to take effect" -Level WARNING
        
        try {
            $gpoName = "dsp-breakAD-SMBv1"
            $dcOU = "OU=Domain Controllers,$($domain.DistinguishedName)"
            
            $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
            
            if (-not $gpo) {
                Write-Log "    Creating new GPO: $gpoName" -Level INFO
                $gpo = New-GPO -Name $gpoName -Comment "dsp-breakAD: Enable SMBv1" -ErrorAction Stop
                Write-Log "      [+] GPO created" -Level SUCCESS
            }
            else {
                Write-Log "    [*] GPO already exists" -Level INFO
            }
            
            try {
                New-GPLink -Name $gpoName -Target $dcOU -ErrorAction Stop | Out-Null
                Write-Log "      [+] GPO linked to Domain Controllers OU" -Level SUCCESS
            }
            catch {
                Write-Log "      [*] GPO link already exists" -Level INFO
            }
            
            Set-GPPrefRegistryValue -Name $gpoName -Context Computer -Action Update -Key "HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters" -ValueName "SMB1" -Value 1 -Type DWORD -ErrorAction Stop | Out-Null
            Write-Log "      [+] Registry preference set (SMB1 = 1)" -Level SUCCESS
            
            Write-Log "    Refreshing Group Policy on Domain Controllers..." -Level INFO
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            foreach ($dcItem in $domainControllers) {
                try {
                    Invoke-Command -ComputerName $dcItem.HostName -ScriptBlock { gpupdate /force /wait:0 } -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "      [+] GPO refresh initiated on $($dcItem.HostName)" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error refreshing GPO on $($dcItem.HostName): $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] SMBv1 modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 6: ADD ANONYMOUS TO PRE-WINDOWS 2000 COMPATIBLE ACCESS
    ################################################################################
    
    Write-Log "PHASE 6: Add Anonymous to Pre-Windows 2000 Compatible Access" -Level INFO
    
    if ($config['InfrastructureSecurity_AddAnonymousPre2000'] -eq 'true') {
        Write-Log "  Adding Anonymous Logon to group..." -Level INFO
        
        try {
            $groupName = "Pre-Windows 2000 Compatible Access"
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
            
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            $hasAnonymous = $members | Where-Object { $_.SID -eq "S-1-5-7" } -ErrorAction SilentlyContinue
            
            if ($null -eq $hasAnonymous) {
                $groupADSI = [ADSI]"LDAP://$($group.DistinguishedName)"
                $groupADSI.Add("LDAP://<SID=S-1-5-7>")
                $groupADSI.SetInfo()
                
                Write-Log "    [+] Anonymous Logon added" -Level SUCCESS
            }
            else {
                Write-Log "    [+] Anonymous Logon already member" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Anonymous to Pre-2000 modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 7: DISABLE AdminSDHolder SDProp PROTECTION
    ################################################################################
    
    Write-Log "PHASE 7: Disable AdminSDHolder SDProp Protection on Operator Groups" -Level INFO
    
    if ($config['InfrastructureSecurity_DisableAdminSDHolder'] -eq 'true') {
        Write-Log "  Removing AdminSDHolder protection from Operator groups..." -Level INFO
        
        try {
            $operatorGroups = @("Backup Operators", "Account Operators", "Print Operators")
            
            foreach ($groupName in $operatorGroups) {
                Write-Log "    Processing group: $groupName" -Level INFO
                
                try {
                    $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
                    $groupADSI = [ADSI]"LDAP://$($group.DistinguishedName)"
                    
                    # Set adminCount to 0 to remove from AdminSDHolder protection
                    $groupADSI.Put("adminCount", 0)
                    $groupADSI.SetInfo()
                    
                    Write-Log "      [+] Removed from AdminSDHolder protection" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] AdminSDHolder modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 8: SET DANGEROUS TRUST ATTRIBUTES
    ################################################################################
    
    Write-Log "PHASE 8: Set Dangerous Trust Attributes" -Level INFO
    
    if ($config['InfrastructureSecurity_DangerousTrustAttribute'] -eq 'true') {
        Write-Log "  Setting dangerous trust attributes..." -Level INFO
        
        try {
            # Get all trusts in the domain
            $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
            
            if ($trusts) {
                foreach ($trust in $trusts) {
                    Write-Log "    Processing trust: $($trust.Name)" -Level INFO
                    
                    try {
                        # Set TrustDirection to Bidirectional if not already
                        if ($trust.Direction -ne "Bidirectional") {
                            Set-ADTrust -Identity $trust.Name -Direction Bidirectional -ErrorAction Stop
                            Write-Log "      [+] Set to Bidirectional" -Level SUCCESS
                        }
                        
                        # Enable SIDHistory on trust (dangerous)
                        Set-ADTrust -Identity $trust.Name -SIDHistoryEnabled $true -ErrorAction Stop
                        Write-Log "      [+] SIDHistory enabled on trust" -Level SUCCESS
                    }
                    catch {
                        Write-Log "      [!] Error: $_" -Level WARNING
                    }
                }
            }
            else {
                Write-Log "    [*] No trusts found in domain" -Level INFO
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Dangerous trust attributes disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 9: ADD WELL-KNOWN PRIVILEGED SIDs TO SIDHistory
    ################################################################################
    
    Write-Log "PHASE 9: Add Well-Known Privileged SIDs to SIDHistory" -Level INFO
    
    if ($config['InfrastructureSecurity_AddPrivilegedSIDHistory'] -eq 'true') {
        Write-Log "  Adding privileged SIDs to user SIDHistory..." -Level INFO
        
        try {
            # Well-known privileged SIDs to add
            $privilegedSIDs = @(
                "S-1-5-32-548",  # Account Operators
                "S-1-5-32-549",  # Server Operators
                "S-1-5-32-550"   # Print Operators
            )
            
            # Find test user to add SIDHistory to
            $testUsers = Get-ADUser -Filter "Name -like 'break-*'" -ErrorAction SilentlyContinue | Select-Object -First 3
            
            if ($testUsers) {
                foreach ($user in $testUsers) {
                    Write-Log "    Processing user: $($user.Name)" -Level INFO
                    
                    try {
                        foreach ($sid in $privilegedSIDs) {
                            # Use ADSI to add SIDHistory
                            $userADSI = [ADSI]"LDAP://$($user.DistinguishedName)"
                            $userADSI.PsBase.InvokeSet("SIDHistory", $sid)
                            $userADSI.SetInfo()
                            
                            Write-Log "      [+] Added SID $sid to SIDHistory" -Level SUCCESS
                        }
                    }
                    catch {
                        Write-Log "      [!] Error adding SIDHistory: $_" -Level WARNING
                    }
                }
            }
            else {
                Write-Log "    [*] No test users found (create users first)" -Level INFO
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] SIDHistory modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 10: MODIFY SCHEMA PERMISSIONS
    ################################################################################
    
    Write-Log "PHASE 10: Modify Schema Permissions" -Level INFO
    
    if ($config['InfrastructureSecurity_ModifySchemaPermissions'] -eq 'true') {
        Write-Log "  Modifying schema object permissions..." -Level INFO
        
        try {
            $rootDSE = Get-ADRootDSE
            $schemaNC = $rootDSE.schemaNamingContext
            
            # Get schema object
            $schema = Get-ADObject -Identity $schemaNC -ErrorAction Stop
            
            Write-Log "    Schema DN: $schemaNC" -Level INFO
            
            # Grant Authenticated Users write access to schema (dangerous)
            try {
                $schemaADSI = [ADSI]"LDAP://$schemaNC"
                $acl = $schemaADSI.PsBase.ObjectSecurity
                
                # Get Authenticated Users SID
                $authUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")
                
                # Create rule for Write access
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $authUsersSID,
                    [System.DirectoryServices.ActiveDirectoryRights]::GenericWrite,
                    [System.Security.AccessControl.AccessControlType]::Allow
                )
                
                $acl.AddAccessRule($rule)
                $schemaADSI.PsBase.ObjectSecurity = $acl
                
                Write-Log "      [+] Added GenericWrite permission for Authenticated Users" -Level SUCCESS
            }
            catch {
                Write-Log "      [!] Error modifying schema ACL: $_" -Level WARNING
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Schema permissions modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 11: UNSECURED DNS CONFIGURATION
    ################################################################################
    
    Write-Log "PHASE 11: Configure Unsecured DNS Updates" -Level INFO
    
    if ($config['InfrastructureSecurity_UnsecuredDNS'] -eq 'true') {
        Write-Log "  Configuring DNS to allow unsecured updates..." -Level INFO
        
        try {
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dcItem in $domainControllers) {
                Write-Log "    Processing DC: $($dcItem.HostName)" -Level INFO
                
                try {
                    # Configure DNS zone to allow non-secure dynamic updates
                    Invoke-Command -ComputerName $dcItem.HostName -ScriptBlock {
                        param($domainName)
                        
                        # Get DNS zone
                        $zone = Get-DnsServerZone -Name $domainName -ErrorAction SilentlyContinue
                        
                        if ($zone) {
                            # Set zone to allow non-secure updates
                            Set-DnsServerZoneAging -Name $domainName -Aging $true -ErrorAction SilentlyContinue
                            Set-DnsServerPrimaryZone -Name $domainName -DynamicUpdate NonsecureAndSecure -ErrorAction Stop
                            Write-Output "Updated"
                        }
                        else {
                            Write-Output "Zone not found"
                        }
                    } -ArgumentList $domain.Name -ErrorAction Stop | ForEach-Object {
                        Write-Log "      [+] DNS zone configured: $_" -Level SUCCESS
                    }
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] DNS configuration disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    Write-Log "========================================" -Level INFO
    Write-Log "Module 01: Infrastructure Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Status: COMPLETE" -Level SUCCESS
    Write-Log "" -Level INFO
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity