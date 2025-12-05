function Invoke-ModuleAccountSecurity {
    param([Parameter(Mandatory=$true)][hashtable]$Environment)
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    $rwdcFQDN = if ($Environment.DomainController.HostName) { $Environment.DomainController.HostName } else { $domain.PDCEmulator }
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 04: Account Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # BdActr24-26: Disabled + protected groups
    Write-Host "Disabling accounts and adding to protected groups..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        for ($i = 24; $i -le 26; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
            if ($u) {
                if ($i -eq 24 -and $aoGroup) {
                    Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                    Disable-ADAccount -Identity $u -ErrorAction SilentlyContinue
                }
                elseif ($i -eq 25 -and $boGroup) {
                    Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                    Disable-ADAccount -Identity $u -ErrorAction SilentlyContinue
                }
                elseif ($i -eq 26 -and $soGroup) {
                    Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                    Disable-ADAccount -Identity $u -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Host "  [+] Disabled 3 accounts and added to protected groups" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr27-29: Ephemeral memberships
    Write-Host "Creating ephemeral memberships..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        for ($i = 27; $i -le 29; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
            if ($u) {
                if ($i -eq 27 -and $aoGroup) {
                    Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 100
                    Remove-ADGroupMember -Identity $aoGroup -Members $u -Confirm:$false -ErrorAction SilentlyContinue
                }
                elseif ($i -eq 28 -and $boGroup) {
                    Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 100
                    Remove-ADGroupMember -Identity $boGroup -Members $u -Confirm:$false -ErrorAction SilentlyContinue
                }
                elseif ($i -eq 29 -and $soGroup) {
                    Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 100
                    Remove-ADGroupMember -Identity $soGroup -Members $u -Confirm:$false -ErrorAction SilentlyContinue
                }
            }
        }
        Write-Host "  [+] Created 3 ephemeral memberships" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr30-81: Assign to privileged groups (52 accounts)
    Write-Host "Assigning bad actors to privileged groups..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        $daGroup = Get-ADGroup -Filter { SamAccountName -eq "Domain Admins" } -ErrorAction SilentlyContinue
        
        $assignedCount = 0
        
        # BdActr30-42 to Account Operators (13 accounts)
        if ($aoGroup) {
            for ($i = 30; $i -le 42; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        # BdActr43-55 to Backup Operators (13 accounts)
        if ($boGroup) {
            for ($i = 43; $i -le 55; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        # BdActr56-68 to Server Operators (13 accounts)
        if ($soGroup) {
            for ($i = 56; $i -le 68; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        # BdActr69-81 to Domain Admins (13 accounts)
        if ($daGroup) {
            for ($i = 69; $i -le 81; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $daGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        Write-Host "  [+] Assigned $assignedCount bad actors to privileged groups" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr82-83: Set adminCount = 1 with inheritance enabled
    Write-Host "Configuring adminCount with inheritance..." -ForegroundColor Yellow
    try {
        for ($i = 82; $i -le 83; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
            if ($u) {
                Set-ADUser -Identity $u -Replace @{"adminCount" = 1} -ErrorAction SilentlyContinue
            }
        }
        Write-Host "  [+] Set adminCount on 2 accounts" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr85: Primary Group ID = 516 (Domain Controllers)
    Write-Host "Setting primary group to Domain Controllers..." -ForegroundColor Yellow
    try {
        $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`85" } -ErrorAction SilentlyContinue
        if ($u) {
            Set-ADUser -Identity $u -Replace @{"primaryGroupID" = 516} -ErrorAction SilentlyContinue
            Write-Host "  [+] Set primaryGroupID to 516 (Domain Controllers)" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr86: Primary Group ID = 513 (Domain Users)
    Write-Host "Setting primary group to Domain Users..." -ForegroundColor Yellow
    try {
        $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`86" } -ErrorAction SilentlyContinue
        if ($u) {
            Set-ADUser -Identity $u -Replace @{"primaryGroupID" = 513} -ErrorAction SilentlyContinue
            Write-Host "  [+] Set primaryGroupID to 513 (Domain Users)" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr87-88: Deny read on primaryGroupID
    Write-Host "Denying read on primaryGroupID..." -ForegroundColor Yellow
    try {
        $primaryGroupIDGUID = "bf967a00-0de6-11d0-a285-00aa003049e2"
        $everyone = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $aceRight = [System.DirectoryServices.ActiveDirectoryRights]"ReadProperty"
        $aceType = [System.Security.AccessControl.AccessControlType]"Deny"
        $aceInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]"None"
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($everyone, $aceRight, $aceType, $primaryGroupIDGUID, $aceInheritance)
        
        for ($i = 87; $i -le 88; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
            if ($u) {
                $userObj = [ADSI]("LDAP://$rwdcFQDN/$($u.DistinguishedName)")
                $userObj.psbase.objectSecurity.AddAccessRule($ace)
                $userObj.psbase.commitchanges()
            }
        }
        Write-Host "  [+] Denied read on primaryGroupID for 2 accounts" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActr90-91: Add to DNSAdmins
    Write-Host "Adding to DNSAdmins group..." -ForegroundColor Yellow
    try {
        $dnsGroup = Get-ADGroup -Filter { SamAccountName -eq "DnsAdmins" } -ErrorAction SilentlyContinue
        if ($dnsGroup) {
            for ($i = 90; $i -le 91; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActr$domainNetBIOS`$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $dnsGroup -Members $u -ErrorAction SilentlyContinue
                }
            }
            Write-Host "  [+] Added 2 members to DnsAdmins" -ForegroundColor Green
            $successCount++
        }
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    Write-Host "Module 04 completed" -ForegroundColor Green
    Write-Host ""
    
    if ($errorCount -gt $successCount) { return $false }
    return $true
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity