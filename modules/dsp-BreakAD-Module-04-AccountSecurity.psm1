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
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 04: Account Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "=== MODULE 04: Account Security ===" -ForegroundColor Cyan
    Write-Host "" -ForegroundColor Cyan
    # Force password refresh on Bad Actors
    Write-Host "Forcing password refresh cycles..." -ForegroundColor Yellow
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
        Write-Host "  [+] Forced password refresh on $refreshCount accounts" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Add computer accounts to privileged groups
    Write-Host "Adding computers to privileged groups..." -ForegroundColor Yellow
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
        Write-Host "  [+] Added $addedCount computers to privileged groups" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Add disabled accounts to protected groups
    Write-Host "Adding disabled accounts to protected groups..." -ForegroundColor Yellow
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
        Write-Host "  [+] Added $disabledCount disabled accounts to protected groups" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Ephemeral admin memberships
    Write-Host "Creating ephemeral admin memberships..." -ForegroundColor Yellow
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
        Write-Host "  [+] Created $ephemeralCount ephemeral memberships" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Assign 50+ bad actors to privileged groups
    Write-Host "Assigning 50+ bad actors to privileged groups..." -ForegroundColor Yellow
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
        Write-Host "  [+] Assigned $assignedCount bad actors to privileged groups" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Set adminCount=1 with inheritance
    Write-Host "Setting adminCount=1 with inheritance enabled..." -ForegroundColor Yellow
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
        Write-Host "  [+] Set adminCount on $adminCountSet accounts" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Non-default primary group IDs
    Write-Host "Configuring non-default primary group IDs..." -ForegroundColor Yellow
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
        Write-Host "  [+] Set primaryGroupID on $primaryGroupSet accounts" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Unreadable primary group IDs
    Write-Host "Making primary group IDs unreadable..." -ForegroundColor Yellow
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
        Write-Host "  [+] Made primaryGroupID unreadable on $unreadableCount accounts" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Pre-Windows 2000 Compatible Access
    Write-Host "Adding to Pre-Windows 2000 Compatible Access..." -ForegroundColor Yellow
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
        Write-Host "  [+] Added $prewCount members to Pre-Windows 2000 Compatible Access" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Weak password policy
    Write-Host "Creating weak password policy (PSO)..." -ForegroundColor Yellow
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
            Write-Host "  [+] Created weak password policy PSO" -ForegroundColor Green
        }
        else {
            Write-Host "  [!] PSO already exists" -ForegroundColor Yellow
        }
    }
    catch { Write-Host "  [!] PSO creation skipped" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # Clear Protected Users
    Write-Host "Clearing Protected Users group..." -ForegroundColor Yellow
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
        Write-Host "  [+] Cleared $clearedCount members from Protected Users" -ForegroundColor Green
    }
    catch { Write-Host "  [!] Error: $_" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    # DNSAdmins
    Write-Host "Adding non-admins to DNSAdmins..." -ForegroundColor Yellow
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
        Write-Host "  [+] Added $dnsCount members to DnsAdmins" -ForegroundColor Green
    }
    catch { Write-Host "  [!] DNSAdmins not found or DNS not installed" -ForegroundColor Yellow }
    Write-Host "" -ForegroundColor Cyan
    Write-Host "Module 04 completed" -ForegroundColor Green
    Write-Host "" -ForegroundColor Cyan
    
    if ($errorCount -gt $successCount) {
        return $false
    }
    return $true
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity