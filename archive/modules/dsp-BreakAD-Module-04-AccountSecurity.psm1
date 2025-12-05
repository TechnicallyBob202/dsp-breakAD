function Invoke-ModuleAccountSecurity {
    param([Parameter(Mandatory=$true)][hashtable]$Environment)
    
    $adDomainDN = $Environment.Domain.DistinguishedName
    $adDomainNetBIOS = $Environment.Domain.NetBIOSName
    $adDomainRwdcPdcFsmoFQDN = $Environment.Domain.PDCEmulator
    $adDomainSID = $Environment.Domain.DomainSID.Value
    $OU = "OU=TEST,$adDomainDN"
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 04: Account Security" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    $accountOperatorsStringFormat = "S-1-5-32-548"
    $accountOperatorsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($accountOperatorsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    $backupOperatorsStringFormat = "S-1-5-32-551"
    $backupOperatorsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($backupOperatorsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    $serverOperatorsStringFormat = "S-1-5-32-549"
    $serverOperatorsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($serverOperatorsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    $domainAdminsStringFormat = $adDomainSID + "-512"
    $domainAdminsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($domainAdminsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    

    
    # Ephemeral Admins (27-29)
    Write-Host "Creating ephemeral memberships..." -ForegroundColor Yellow
    
    $ephemeralAccounts = @(
        @{ Num = 27; Group = $accountOperatorsPrincipalName; GroupName = "Account Operators" }
        @{ Num = 28; Group = $backupOperatorsPrincipalName; GroupName = "Backup Operators" }
        @{ Num = 29; Group = $serverOperatorsPrincipalName; GroupName = "Server Operators" }
    )
    
    foreach ($account in $ephemeralAccounts) {
        $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + $account.Num
        $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
        $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $badAct0rObject = $adsiSearcher.FindOne()
        
        if ($badAct0rObject) {
            $adsiSearcher2 = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($account.Group.Split('\')[1])))"
            $adsiSearcher2.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
            $groupObject = $adsiSearcher2.FindOne()
            
            if ($groupObject) {
                try {
                    $group = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($groupObject.Properties.distinguishedname[0]))
                    $group.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                    $group.SetInfo()
                    $group.RefreshCache()
                    Start-Sleep -Milliseconds 500
                    $group.Remove("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                    $group.SetInfo()
                    Write-Host "  [+] '$adDomainNetBIOS\$badAct0rSamAccountName' added and removed from $($account.GroupName)" -ForegroundColor Green
                } catch {
                    Write-Host "  [!] Error with $badAct0rSamAccountName`: $_" -ForegroundColor Yellow
                }
            }
        }
    }
    Write-Host ""
    
    # Bulk group assignments (30-81)
    Write-Host "Assigning accounts to privileged groups..." -ForegroundColor Yellow
    
    $accountsOU = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $OU)
    $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=BdActr*))"
    $adsiSearcher.SearchRoot = $accountsOU
    $badAct0rObjects = $adsiSearcher.FindAll()
    
    $i = 29
    $assigned = 0
    
    if ($badAct0rObjects) {
        # Get group objects
        $adsiSearcher_ao = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($accountOperatorsPrincipalName.Split('\')[1])))"
        $adsiSearcher_ao.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $aoGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($adsiSearcher_ao.FindOne().Properties.distinguishedname[0]))
        
        $adsiSearcher_bo = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($backupOperatorsPrincipalName.Split('\')[1])))"
        $adsiSearcher_bo.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $boGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($adsiSearcher_bo.FindOne().Properties.distinguishedname[0]))
        
        $adsiSearcher_so = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($serverOperatorsPrincipalName.Split('\')[1])))"
        $adsiSearcher_so.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $soGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($adsiSearcher_so.FindOne().Properties.distinguishedname[0]))
        
        $adsiSearcher_da = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($domainAdminsPrincipalName.Split('\')[1])))"
        $adsiSearcher_da.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $daGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($adsiSearcher_da.FindOne().Properties.distinguishedname[0]))
        
        $badAct0rObjects | Where-Object { [decimal]$_.Properties.samaccountname[0].Replace("BdActr$adDomainNetBIOS","") -ge 30 -And [decimal]$_.Properties.samaccountname[0].Replace("BdActr$adDomainNetBIOS","") -le 81 } | ForEach-Object {
            $i++
            try {
                if ($i -ge 30 -And $i -le 42) {
                    $aoGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($_.properties.distinguishedname[0]))
                    $aoGroup.SetInfo()
                    $assigned++
                }
                elseif ($i -ge 43 -And $i -le 55) {
                    $boGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($_.properties.distinguishedname[0]))
                    $boGroup.SetInfo()
                    $assigned++
                }
                elseif ($i -ge 56 -And $i -le 68) {
                    $soGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($_.properties.distinguishedname[0]))
                    $soGroup.SetInfo()
                    $assigned++
                }
                elseif ($i -ge 69 -And $i -le 81) {
                    $daGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($_.properties.distinguishedname[0]))
                    $daGroup.SetInfo()
                    $assigned++
                }
            } catch { }
        }
    }
    Write-Host "  [+] Assigned $assigned accounts to privileged groups" -ForegroundColor Green
    Write-Host ""
    
    # AdminCount and primaryGroupID settings
    Write-Host "Configuring adminCount and primaryGroupID..." -ForegroundColor Yellow
    
    # BdActr82-83: AdminCount = 1
    for ($i = 82; $i -le 83; $i++) {
        $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + $i
        $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
        $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $badAct0rObject = $adsiSearcher.FindOne()
        
        if ($badAct0rObject) {
            try {
                $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                $badAct0rAccount.Put("adminCount", 1)
                $badAct0rAccount.SetInfo()
            } catch { }
        }
    }
    
    # BdActr85: primaryGroupID = 516 (Domain Controllers)
    $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + "85"
    $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
    $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
    $badAct0rObject = $adsiSearcher.FindOne()
    
    if ($badAct0rObject) {
        try {
            $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
            $badAct0rAccount.Put("primaryGroupID", 516)
            $badAct0rAccount.SetInfo()
        } catch { }
    }
    
    # BdActr86: primaryGroupID = 513 (Domain Users)
    $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + "86"
    $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
    $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
    $badAct0rObject = $adsiSearcher.FindOne()
    
    if ($badAct0rObject) {
        try {
            $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
            $badAct0rAccount.Put("primaryGroupID", 513)
            $badAct0rAccount.SetInfo()
        } catch { }
    }
    
    # BdActr87-88: Deny read on primaryGroupID
    $schemaIDGUIDScopedAttribute = "bf967a00-0de6-11d0-a285-00aa003049e2"
    $everyoneStringFormat = "S-1-1-0"
    $everyonePrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($everyoneStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    $everyoneSecurityIdentifier = [System.Security.Principal.SecurityIdentifier] $everyoneStringFormat
    $everyoneIdentityReference = [System.Security.Principal.IdentityReference] $everyoneSecurityIdentifier
    $aceRight = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty"
    $aceType = [System.Security.AccessControl.AccessControlType] "Deny"
    $aceInheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
    $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $everyoneIdentityReference,$aceRight,$aceType,$schemaIDGUIDScopedAttribute,$aceInheritanceType
    
    for ($i = 87; $i -le 88; $i++) {
        $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + $i
        $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
        $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $badAct0rObject = $adsiSearcher.FindOne()
        
        if ($badAct0rObject) {
            try {
                $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                $badAct0rAccount.psbase.objectSecurity.AddAccessRule($ace)
                $badAct0rAccount.psbase.commitchanges()
            } catch { }
        }
    }
    
    Write-Host "  [+] AdminCount and primaryGroupID configured" -ForegroundColor Green
    Write-Host ""
    
    # BdActr90-91: DNSAdmins
    Write-Host "Adding to DnsAdmins..." -ForegroundColor Yellow
    $dnsAdminsStringFormat = "S-1-5-21-3623811015-3361044348-30300820-1101"
    $adsiSearcher_dns = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=DnsAdmins))"
    $adsiSearcher_dns.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
    $dnsAdminsObject = $adsiSearcher_dns.FindOne()
    
    if ($dnsAdminsObject) {
        $dnsAdminsGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($dnsAdminsObject.Properties.distinguishedname[0]))
        
        for ($i = 90; $i -le 91; $i++) {
            $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + $i
            $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
            $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
            $badAct0rObject = $adsiSearcher.FindOne()
            
            if ($badAct0rObject) {
                try {
                    $dnsAdminsGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                    $dnsAdminsGroup.SetInfo()
                } catch { }
            }
        }
        Write-Host "  [+] Added to DnsAdmins" -ForegroundColor Green
    }
    Write-Host ""
    
    Write-Host "Module 04 completed" -ForegroundColor Green
    Write-Host ""
    return $true
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity