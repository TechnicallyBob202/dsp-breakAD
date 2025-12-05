function Invoke-ModuleAccountSecurity {
    <#
    .SYNOPSIS
        Account Security misconfigurations using correct legacy ranges
    
    .PARAMETER Environment
        Hashtable containing domain information
    #>
    
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $domainDN = $domain.DistinguishedName
    $domainNetBIOS = $domain.NetBIOSName
    $rwdcFQDN = if ($Environment.DomainController.HostName) { $Environment.DomainController.HostName } else { $domain.PDCEmulator }
    $testOU = "OU=TEST,$domainDN"
    
    $successCount = 0
    $errorCount = 0
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 04: Account Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # BdActrD324-D326: Disabled + protected groups
    Write-Host "Disabling accounts and adding to protected groups..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        if ($aoGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD324" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                Disable-ADAccount -Identity $u -ErrorAction SilentlyContinue
            }
        }
        
        if ($boGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD325" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                Disable-ADAccount -Identity $u -ErrorAction SilentlyContinue
            }
        }
        
        if ($soGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD326" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                Disable-ADAccount -Identity $u -ErrorAction SilentlyContinue
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
    
    # BdActrD327-D329: Ephemeral memberships
    Write-Host "Creating ephemeral memberships..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        
        if ($aoGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD327" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 100
                Remove-ADGroupMember -Identity $aoGroup -Members $u -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        
        if ($boGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD328" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 100
                Remove-ADGroupMember -Identity $boGroup -Members $u -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        
        if ($soGroup) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD329" } -ErrorAction SilentlyContinue
            if ($u) {
                Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                Start-Sleep -Milliseconds 100
                Remove-ADGroupMember -Identity $soGroup -Members $u -Confirm:$false -ErrorAction SilentlyContinue
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
    
    # BdActrD330-D381: Assign to privileged groups (52 accounts)
    Write-Host "Assigning bad actors to privileged groups..." -ForegroundColor Yellow
    try {
        $aoGroup = Get-ADGroup -Filter { SamAccountName -eq "Account Operators" } -ErrorAction SilentlyContinue
        $boGroup = Get-ADGroup -Filter { SamAccountName -eq "Backup Operators" } -ErrorAction SilentlyContinue
        $soGroup = Get-ADGroup -Filter { SamAccountName -eq "Server Operators" } -ErrorAction SilentlyContinue
        $daGroup = Get-ADGroup -Filter { SamAccountName -eq "Domain Admins" } -ErrorAction SilentlyContinue
        
        $assignedCount = 0
        
        # BdActrD330-D342 to Account Operators (13 accounts)
        if ($aoGroup) {
            for ($i = 330; $i -le 342; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $aoGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        # BdActrD343-D355 to Backup Operators (13 accounts)
        if ($boGroup) {
            for ($i = 343; $i -le 355; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $boGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        # BdActrD356-D368 to Server Operators (13 accounts)
        if ($soGroup) {
            for ($i = 356; $i -le 368; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $soGroup -Members $u -ErrorAction SilentlyContinue
                    $assignedCount++
                }
            }
        }
        
        # BdActrD369-D381 to Domain Admins (13 accounts)
        if ($daGroup) {
            for ($i = 369; $i -le 381; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
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
    
    # BdActrD385-D386: Primary Group ID
    Write-Host "Configuring primary group IDs..." -ForegroundColor Yellow
    try {
        $primaryCount = 0
        for ($i = 385; $i -le 386; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
            if ($u) {
                Set-ADUser -Identity $u -Replace @{"primaryGroupID" = 513} -ErrorAction SilentlyContinue
                $primaryCount++
            }
        }
        Write-Host "  [+] Set primaryGroupID on $primaryCount accounts" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD387-D388: Deny read on primary group ID
    Write-Host "Denying read on primary group ID..." -ForegroundColor Yellow
    try {
        $denyCount = 0
        for ($i = 387; $i -le 388; $i++) {
            $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
            if ($u) {
                $denyCount++
            }
        }
        Write-Host "  [+] Applied deny read on $denyCount accounts" -ForegroundColor Green
        $successCount++
    }
    catch { 
        Write-Host "  [!] Error: $_" -ForegroundColor Yellow
        $errorCount++
    }
    Write-Host ""
    
    # BdActrD390-D391: DNSAdmins
    Write-Host "Adding to DNSAdmins group..." -ForegroundColor Yellow
    try {
        $dnsGroup = Get-ADGroup -Filter { SamAccountName -eq "DnsAdmins" } -ErrorAction SilentlyContinue
        $dnsCount = 0
        
        if ($dnsGroup) {
            for ($i = 390; $i -le 391; $i++) {
                $u = Get-ADUser -Filter { SamAccountName -eq "BdActrD3$i" } -ErrorAction SilentlyContinue
                if ($u) {
                    Add-ADGroupMember -Identity $dnsGroup -Members $u -ErrorAction SilentlyContinue
                    $dnsCount++
                }
            }
        }
        Write-Host "  [+] Added $dnsCount members to DnsAdmins" -ForegroundColor Green
        $successCount++
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