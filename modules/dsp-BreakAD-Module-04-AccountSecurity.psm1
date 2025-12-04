################################################################################
##
## dsp-BreakAD-Module-04-AccountSecurity.psm1
##
## Configures user and computer accounts with various security misconfigurations
## 
## Author: Bob Lyons
## Version: 1.0.0-20251204
##
################################################################################

function Invoke-ModuleAccountSecurity {
    <#
    .SYNOPSIS
        Configures account security misconfigurations
    
    .DESCRIPTION
        Applies security misconfigurations across user/computer accounts:
        - Force password refresh cycles
        - Add computers to privileged groups
        - Add disabled accounts to protected groups
        - Create ephemeral admin memberships
        - Assign 50+ bad actors to privileged groups
        - Set adminCount=1 with inheritance enabled
        - Configure non-default primary group IDs
        - Make primary group IDs unreadable
        - Add to Pre-Windows 2000 Compatible Access
        - Create weak password policy (PSO)
        - Clear Protected Users group
        - Add non-admins to DNSAdmins
    
    .PARAMETER Environment
        Hashtable with Domain, DomainController, etc.
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domainDN = $Environment.Domain.DistinguishedName
    $domainNetBIOS = $Environment.Domain.NetBIOSName
    $rwdcFQDN = $Environment.DomainController.HostName
    $testOU = "OU=TEST,$domainDN"
    
    Write-Log "" -Level INFO
    Write-Log "=== MODULE 04: Account Security ===" -Level INFO
    Write-Log "" -Level INFO
    
    # Force password refresh on Bad Actors
    Write-Log "Forcing password refresh cycles..." -Level WARNING
    try {
        $badActors = Get-ADUser -Filter { SamAccountName -like "BdActr*" } -SearchBase $testOU -ErrorAction SilentlyContinue
        $refreshCount = 0
        
        foreach ($badActor in $badActors) {
            try {
                $badActorObj = [ADSI]("LDAP://$rwdcFQDN/$($badActor.DistinguishedName)")
                $pwdNeverExpiresSet = ($badActor.UserAccountControl -band 65536) -eq 65536
                
                if ($pwdNeverExpiresSet) {
                    $badActorObj.Put("userAccountControl", $badActor.UserAccountControl -bxor 65536)
                    $badActorObj.SetInfo()
                }
                
                $badActorObj.Put("pwdLastSet", 0)
                $badActorObj.SetInfo()
                $badActorObj.Put("pwdLastSet", -1)
                $badActorObj.SetInfo()
                
                if ($pwdNeverExpiresSet) {
                    $badActorObj.Put("userAccountControl", $badActor.UserAccountControl -bor 65536)
                    $badActorObj.SetInfo()
                }
                
                $refreshCount++
            }
            catch { }
        }
        Write-Log "  [+] Forced password refresh on $refreshCount accounts" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Add computer accounts to privileged groups
    Write-Log "Adding computers to privileged groups..." -Level WARNING
    try {
        $computers = Get-ADComputer -Filter * -SearchBase $testOU -ErrorAction SilentlyContinue
        $accountOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $backupOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $serverOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        $addedCount = 0
        $i = 0
        foreach ($computer in $computers) {
            $i++
            try {
                if ($i -ge 1 -and $i -le 5 -and $accountOpsGroup) {
                    Add-ADGroupMember -Identity $accountOpsGroup -Members $computer -ErrorAction SilentlyContinue
                    $addedCount++
                }
                elseif ($i -ge 6 -and $i -le 10 -and $backupOpsGroup) {
                    Add-ADGroupMember -Identity $backupOpsGroup -Members $computer -ErrorAction SilentlyContinue
                    $addedCount++
                }
                elseif ($i -ge 11 -and $i -le 15 -and $serverOpsGroup) {
                    Add-ADGroupMember -Identity $serverOpsGroup -Members $computer -ErrorAction SilentlyContinue
                    $addedCount++
                }
            }
            catch { }
        }
        Write-Log "  [+] Added $addedCount computers to privileged groups" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Add disabled accounts to protected groups
    Write-Log "Adding disabled accounts to protected groups..." -Level WARNING
    try {
        $accountOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $backupOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $serverOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        $disabledCount = 0
        
        for ($i = 24; $i -le 26; $i++) {
            $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
            if ($badActor) {
                try {
                    if ($i -eq 24 -and $accountOpsGroup) {
                        Add-ADGroupMember -Identity $accountOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        Set-ADUser -Identity $badActor -Enabled $false
                        $disabledCount++
                    }
                    elseif ($i -eq 25 -and $backupOpsGroup) {
                        Add-ADGroupMember -Identity $backupOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        Set-ADUser -Identity $badActor -Enabled $false
                        $disabledCount++
                    }
                    elseif ($i -eq 26 -and $serverOpsGroup) {
                        Add-ADGroupMember -Identity $serverOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        Set-ADUser -Identity $badActor -Enabled $false
                        $disabledCount++
                    }
                }
                catch { }
            }
        }
        Write-Log "  [+] Added $disabledCount disabled accounts to protected groups" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Ephemeral admin memberships
    Write-Log "Creating ephemeral admin memberships..." -Level WARNING
    try {
        $accountOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $backupOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $serverOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        $ephemeralCount = 0
        
        for ($i = 27; $i -le 29; $i++) {
            $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
            if ($badActor) {
                try {
                    if ($i -eq 27 -and $accountOpsGroup) {
                        Add-ADGroupMember -Identity $accountOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 100
                        Remove-ADGroupMember -Identity $accountOpsGroup -Members $badActor -Confirm:$false -ErrorAction SilentlyContinue
                        $ephemeralCount++
                    }
                    elseif ($i -eq 28 -and $backupOpsGroup) {
                        Add-ADGroupMember -Identity $backupOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 100
                        Remove-ADGroupMember -Identity $backupOpsGroup -Members $badActor -Confirm:$false -ErrorAction SilentlyContinue
                        $ephemeralCount++
                    }
                    elseif ($i -eq 29 -and $serverOpsGroup) {
                        Add-ADGroupMember -Identity $serverOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        Start-Sleep -Milliseconds 100
                        Remove-ADGroupMember -Identity $serverOpsGroup -Members $badActor -Confirm:$false -ErrorAction SilentlyContinue
                        $ephemeralCount++
                    }
                }
                catch { }
            }
        }
        Write-Log "  [+] Created $ephemeralCount ephemeral memberships" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Assign 50+ bad actors to privileged groups
    Write-Log "Assigning 50+ bad actors to privileged groups..." -Level WARNING
    try {
        $accountOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $backupOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $serverOpsGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        $domainAdminsGroup = Get-ADGroup -Filter { SamAccountName -eq "Domain Admins" } -ErrorAction SilentlyContinue
        $assignedCount = 0
        $i = 29
        
        for ($num = 30; $num -le 81; $num++) {
            $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$num" } -ErrorAction SilentlyContinue
            if ($badActor) {
                $i++
                try {
                    if ($i -ge 30 -and $i -le 42 -and $accountOpsGroup) {
                        Add-ADGroupMember -Identity $accountOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        $assignedCount++
                    }
                    elseif ($i -ge 43 -and $i -le 55 -and $backupOpsGroup) {
                        Add-ADGroupMember -Identity $backupOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        $assignedCount++
                    }
                    elseif ($i -ge 56 -and $i -le 68 -and $serverOpsGroup) {
                        Add-ADGroupMember -Identity $serverOpsGroup -Members $badActor -ErrorAction SilentlyContinue
                        $assignedCount++
                    }
                    elseif ($i -ge 69 -and $i -le 81 -and $domainAdminsGroup) {
                        Add-ADGroupMember -Identity $domainAdminsGroup -Members $badActor -ErrorAction SilentlyContinue
                        $assignedCount++
                    }
                }
                catch { }
            }
        }
        Write-Log "  [+] Assigned $assignedCount bad actors to privileged groups" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Set adminCount=1 with inheritance
    Write-Log "Setting adminCount=1 with inheritance enabled..." -Level WARNING
    try {
        $adminCountSet = 0
        for ($i = 82; $i -le 83; $i++) {
            $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
            if ($badActor) {
                try {
                    Set-ADUser -Identity $badActor -Replace @{"adminCount" = 1}
                    $badActorObj = [ADSI]("LDAP://$rwdcFQDN/$($badActor.DistinguishedName)")
                    $dacl = $badActorObj.psbase.objectSecurity
                    if ($dacl.get_AreAccessRulesProtected()) {
                        $dacl.SetAccessRuleProtection($false, $true)
                        $badActorObj.psbase.commitchanges()
                    }
                    $adminCountSet++
                }
                catch { }
            }
        }
        Write-Log "  [+] Set adminCount on $adminCountSet accounts" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Non-default primary group IDs
    Write-Log "Configuring non-default primary group IDs..." -Level WARNING
    try {
        $domainControllersGroup = Get-ADGroup -Filter { SamAccountName -eq "Domain Controllers" } -ErrorAction SilentlyContinue
        $primaryGroupSet = 0
        
        if ($domainControllersGroup) {
            for ($i = 84; $i -le 85; $i++) {
                $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
                if ($badActor) {
                    try {
                        Add-ADGroupMember -Identity $domainControllersGroup -Members $badActor -ErrorAction SilentlyContinue
                        Set-ADUser -Identity $badActor -Replace @{"primaryGroupID" = 516}
                        $primaryGroupSet++
                    }
                    catch { }
                }
            }
        }
        Write-Log "  [+] Set primaryGroupID on $primaryGroupSet accounts" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Unreadable primary group IDs
    Write-Log "Making primary group IDs unreadable..." -Level WARNING
    try {
        $primaryGroupIDGUID = "bf967a00-0de6-11d0-a285-00aa003049e2"
        $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty"
        $aceType = [System.Security.AccessControl.AccessControlType]"Deny"
        $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($everyone, $aceRight, $aceType, $primaryGroupIDGUID, $aceInheritance)
        $unreadableCount = 0
        
        for ($i = 86; $i -le 87; $i++) {
            $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
            if ($badActor) {
                try {
                    $badActorObj = [ADSI]("LDAP://$rwdcFQDN/$($badActor.DistinguishedName)")
                    $badActorObj.psbase.objectSecurity.AddAccessRule($ace)
                    $badActorObj.psbase.commitchanges()
                    $unreadableCount++
                }
                catch { }
            }
        }
        Write-Log "  [+] Made primaryGroupID unreadable on $unreadableCount accounts" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Pre-Windows 2000 Compatible Access
    Write-Log "Adding to Pre-Windows 2000 Compatible Access..." -Level WARNING
    try {
        $preW2KGroup = Get-ADGroup -Filter { SamAccountName -eq "Pre-Windows 2000 Compatible Access" } -ErrorAction SilentlyContinue
        $prewCount = 0
        
        if ($preW2KGroup) {
            for ($i = 124; $i -le 126; $i++) {
                $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
                if ($badActor) {
                    try {
                        Add-ADGroupMember -Identity $preW2KGroup -Members $badActor -ErrorAction SilentlyContinue
                        $prewCount++
                    }
                    catch { }
                }
            }
        }
        Write-Log "  [+] Added $prewCount members to Pre-Windows 2000 Compatible Access" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Weak password policy
    Write-Log "Creating weak password policy (PSO)..." -Level WARNING
    try {
        $psoContainerDN = "CN=Password Settings Container,CN=System,$domainDN"
        $psoName = "PSO-Weak-Settings"
        $psoExists = Get-ADObject -Filter { Name -eq $psoName } -SearchBase $psoContainerDN -ErrorAction SilentlyContinue
        
        if (-not $psoExists) {
            $psoContainer = [ADSI]("LDAP://$rwdcFQDN/$psoContainerDN")
            $newPSO = $psoContainer.Create("msDS-PasswordSettings", "CN=$psoName")
            $newPSO.Put("msDS-PasswordSettingsPrecedence", 100)
            $newPSO.Put("msDS-MaximumPasswordAge", -1244160000000000)
            $newPSO.Put("msDS-MinimumPasswordLength", 3)
            $newPSO.Put("msDS-PasswordComplexityEnabled", "FALSE")
            $newPSO.Put("msDS-PasswordHistoryLength", 3)
            $newPSO.Put("msDS-PasswordReversibleEncryptionEnabled", "TRUE")
            $newPSO.Put("msDS-LockoutThreshold", 100)
            $newPSO.SetInfo()
            Write-Log "  [+] Created weak password policy PSO" -Level SUCCESS
        }
        else {
            Write-Log "  [!] PSO already exists" -Level WARNING
        }
    }
    catch { Write-Log "  [!] PSO creation skipped" -Level WARNING }
    Write-Log "" -Level INFO
    
    # Clear Protected Users
    Write-Log "Clearing Protected Users group..." -Level WARNING
    try {
        $protectedUsersGroup = Get-ADGroup -Filter { SamAccountName -eq "Protected Users" } -ErrorAction SilentlyContinue
        $clearedCount = 0
        
        if ($protectedUsersGroup) {
            $members = Get-ADGroupMember -Identity $protectedUsersGroup -ErrorAction SilentlyContinue
            foreach ($member in $members) {
                try {
                    Remove-ADGroupMember -Identity $protectedUsersGroup -Members $member -Confirm:$false -ErrorAction SilentlyContinue
                    $clearedCount++
                }
                catch { }
            }
        }
        Write-Log "  [+] Cleared $clearedCount members from Protected Users" -Level SUCCESS
    }
    catch { Write-Log "  [!] Error: $_" -Level WARNING }
    Write-Log "" -Level INFO
    
    # DNSAdmins
    Write-Log "Adding non-admins to DNSAdmins..." -Level WARNING
    try {
        $dnsAdminsGroup = Get-ADGroup -Filter { SamAccountName -eq "DnsAdmins" } -ErrorAction SilentlyContinue
        $dnsCount = 0
        
        if ($dnsAdminsGroup) {
            for ($i = 90; $i -le 91; $i++) {
                $badActor = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS$i" } -ErrorAction SilentlyContinue
                if ($badActor) {
                    try {
                        Add-ADGroupMember -Identity $dnsAdminsGroup -Members $badActor -ErrorAction SilentlyContinue
                        $dnsCount++
                    }
                    catch { }
                }
            }
        }
        Write-Log "  [+] Added $dnsCount members to DnsAdmins" -Level SUCCESS
    }
    catch { Write-Log "  [!] DNSAdmins not found or DNS not installed" -Level WARNING }
    Write-Log "" -Level INFO
    
    Write-Log "Module 04 completed" -Level SUCCESS
    Write-Log "" -Level INFO
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity