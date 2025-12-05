function Invoke-ModuleADDelegations {
    param([Parameter(Mandatory=$true)][hashtable]$Environment)
    
    $adDomainDN = $Environment.Domain.DistinguishedName
    $adDomainNetBIOS = $Environment.Domain.NetBIOSName
    $adDomainRwdcPdcFsmoFQDN = $Environment.Domain.PDCEmulator
    $adDomainDomainControllersContainerDN = $Environment.Domain.DomainControllersContainer
    $adDomainSID = $Environment.Domain.DomainSID.Value
    $OU = "OU=TEST,$adDomainDN"
    
    Write-Host ""
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host "  MODULE 03: AD Delegations" -ForegroundColor Cyan
    Write-Host "===============================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Full Control For This Object And Descendant Objects
    $badAct0rSamAccountName1 = "BdActr" + $adDomainNetBIOS + "7"
    $adsiSearcher1 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName1))"
    $adsiSearcher1.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject1 = $adsiSearcher1.FindOne()
    Write-Host " > Bad Act0r: $($badAct0rObject1.Properties.samaccountname[0]) | $($badAct0rObject1.Properties.userprincipalname[0]) | $($badAct0rObject1.Properties.distinguishedname[0])" -ForegroundColor Cyan
    Try {
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $badAct0rSidStringFormat1 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject1.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier1 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat1
        $badAct0rIdentityReference1 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier1
        $aceRight1 = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
        $aceType1 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType1 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "All"
        $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference1,$aceRight1,$aceType1,$aceInheritanceType1
        $domain.psbase.objectSecurity.AddAccessRule($ace1)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Full Control On Domain NC For All Objects..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host ""
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""

    # Full Control For Descendant Computer Objects
    $badAct0rSamAccountName2 = "BdActr" + $adDomainNetBIOS + "8"
    $adsiSearcher2 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName2))"
    $adsiSearcher2.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject2 = $adsiSearcher2.FindOne()
    Write-Host " > Bad Act0r: $($badAct0rObject2.Properties.samaccountname[0]) | $($badAct0rObject2.Properties.userprincipalname[0]) | $($badAct0rObject2.Properties.distinguishedname[0])" -ForegroundColor Cyan
    Try {
        $schemaIDGUIDScopedObject = "bf967a86-0de6-11d0-a285-00aa003049e2"
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $badAct0rSidStringFormat2 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject2.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier2 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat2
        $badAct0rIdentityReference2 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier2
        $aceRight2 = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
        $aceType2 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType2 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
        $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference2,$aceRight2,$aceType2,$aceInheritanceType2,$schemaIDGUIDScopedObject
        $domain.psbase.objectSecurity.AddAccessRule($ace2)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Full Control On Domain NC For All Computer Objects..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host ""
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""

    # Read/Write Property For UserAccountControl On Descendant Computer Objects
    $badAct0rSamAccountName3 = "BdActr" + $adDomainNetBIOS + "9"
    $adsiSearcher3 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName3))"
    $adsiSearcher3.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject3 = $adsiSearcher3.FindOne()
    Write-Host " > Bad Act0r: $($badAct0rObject3.Properties.samaccountname[0]) | $($badAct0rObject3.Properties.userprincipalname[0]) | $($badAct0rObject3.Properties.distinguishedname[0])" -ForegroundColor Cyan
    Try {
        $schemaIDGUIDScopedObject = "bf967a86-0de6-11d0-a285-00aa003049e2"
        $schemaIDGUIDScopedAttribute = "bf967a68-0de6-11d0-a285-00aa003049e2"
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $badAct0rSidStringFormat3 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject3.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier3 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat3
        $badAct0rIdentityReference3 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier3
        $aceRight3 = [System.DirectoryServices.ActiveDirectoryRights] "ReadProperty,WriteProperty"
        $aceType3 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType3 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "Descendents"
        $ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference3,$aceRight3,$aceType3,$schemaIDGUIDScopedAttribute,$aceInheritanceType3,$schemaIDGUIDScopedObject
        $domain.psbase.objectSecurity.AddAccessRule($ace3)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Read/Write Property For UserAccountControl..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host ""
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""

    # Adding Accounts To Protected Groups (10, 11, 12)
    $accountOperatorsStringFormat = "S-1-5-32-548"
    $accountOperatorsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($accountOperatorsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    $backupOperatorsStringFormat = "S-1-5-32-551"
    $backupOperatorsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($backupOperatorsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    $serverOperatorsStringFormat = "S-1-5-32-549"
    $serverOperatorsPrincipalName = $(New-Object System.Security.Principal.SecurityIdentifier($serverOperatorsStringFormat)).Translate([System.Security.Principal.NTAccount]).Value
    
    # Account Operators - BdActr10
    $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + "10"
    $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
    $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
    $badAct0rObject = $adsiSearcher.FindOne()
    if ($badAct0rObject) {
        $adsiSearcher2 = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($accountOperatorsPrincipalName.Split('\')[1])))"
        $adsiSearcher2.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $accountOperatorsObject = $adsiSearcher2.FindOne()
        Write-Host "Object DN: $($accountOperatorsObject.Properties.distinguishedname[0])" -ForegroundColor Magenta
        Write-Host " > Bad Act0r (New Member): $($badAct0rObject.Properties.samaccountname[0])" -ForegroundColor Cyan
        Try {
            $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
            $accountOperatorsGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($accountOperatorsObject.Properties.distinguishedname[0]))
            $existingMembers = @($accountOperatorsGroup.member)
            if ($existingMembers -notcontains $badAct0rObject.Properties.distinguishedname[0]) {
                $accountOperatorsGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                $accountOperatorsGroup.SetInfo()
            }
            [int]$ADS_PROPERTY_CLEAR = 1
            $badAct0rAccount.PutEx($ADS_PROPERTY_CLEAR, "adminCount", 0)
            $badAct0rAccount.SetInfo()
            Write-Host " > '$adDomainNetBIOS\$badAct0rSamAccountName' Added As Member To '$accountOperatorsPrincipalName'..." -ForegroundColor Green
            Write-Host " > AdminCount Cleared On '$adDomainNetBIOS\$badAct0rSamAccountName'..." -ForegroundColor Green
        } Catch {
            Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
            Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # Backup Operators - BdActr11
    $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + "11"
    $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
    $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
    $badAct0rObject = $adsiSearcher.FindOne()
    if ($badAct0rObject) {
        $adsiSearcher2 = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($backupOperatorsPrincipalName.Split('\')[1])))"
        $adsiSearcher2.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $backupOperatorsObject = $adsiSearcher2.FindOne()
        Write-Host "Object DN: $($backupOperatorsObject.Properties.distinguishedname[0])" -ForegroundColor Magenta
        Write-Host " > Bad Act0r (New Member): $($badAct0rObject.Properties.samaccountname[0])" -ForegroundColor Cyan
        Try {
            $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
            $backupOperatorsGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($backupOperatorsObject.Properties.distinguishedname[0]))
            $existingMembers = @($backupOperatorsGroup.member)
            if ($existingMembers -notcontains $badAct0rObject.Properties.distinguishedname[0]) {
                $backupOperatorsGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                $backupOperatorsGroup.SetInfo()
            }
            [int]$ADS_PROPERTY_CLEAR = 1
            $badAct0rAccount.PutEx($ADS_PROPERTY_CLEAR, "adminCount", 0)
            $badAct0rAccount.SetInfo()
            Write-Host " > '$adDomainNetBIOS\$badAct0rSamAccountName' Added As Member To '$backupOperatorsPrincipalName'..." -ForegroundColor Green
            Write-Host " > AdminCount Cleared On '$adDomainNetBIOS\$badAct0rSamAccountName'..." -ForegroundColor Green
        } Catch {
            Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
            Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # Server Operators - BdActr12
    $badAct0rSamAccountName = "BdActr" + $adDomainNetBIOS + "12"
    $adsiSearcher = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName))"
    $adsiSearcher.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
    $badAct0rObject = $adsiSearcher.FindOne()
    if ($badAct0rObject) {
        $adsiSearcher2 = [adsisearcher]"(&(objectCategory=Group)(objectClass=group)(sAMAccountName=$($serverOperatorsPrincipalName.Split('\')[1])))"
        $adsiSearcher2.SearchRoot = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        $serverOperatorsObject = $adsiSearcher2.FindOne()
        Write-Host "Object DN: $($serverOperatorsObject.Properties.distinguishedname[0])" -ForegroundColor Magenta
        Write-Host " > Bad Act0r (New Member): $($badAct0rObject.Properties.samaccountname[0])" -ForegroundColor Cyan
        Try {
            $badAct0rAccount = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
            $serverOperatorsGroup = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($serverOperatorsObject.Properties.distinguishedname[0]))
            $existingMembers = @($serverOperatorsGroup.member)
            if ($existingMembers -notcontains $badAct0rObject.Properties.distinguishedname[0]) {
                $serverOperatorsGroup.Add("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $($badAct0rObject.Properties.distinguishedname[0]))
                $serverOperatorsGroup.SetInfo()
            }
            [int]$ADS_PROPERTY_CLEAR = 1
            $badAct0rAccount.PutEx($ADS_PROPERTY_CLEAR, "adminCount", 0)
            $badAct0rAccount.SetInfo()
            Write-Host " > '$adDomainNetBIOS\$badAct0rSamAccountName' Added As Member To '$serverOperatorsPrincipalName'..." -ForegroundColor Green
            Write-Host " > AdminCount Cleared On '$adDomainNetBIOS\$badAct0rSamAccountName'..." -ForegroundColor Green
        } Catch {
            Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
            Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    Write-Host ""

    # LAPS and Computer Delegations (13-21)
    $schemaIDGUIDScopedAttribute = "8a771fe0-a36b-4788-aca0-e1ee3692bb64"
    $schemaIDGUIDScopedCAR = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    
    # BdActr17: Replicate Changes All
    $badAct0rSamAccountName1 = "BdActr" + $adDomainNetBIOS + "17"
    $adsiSearcher1 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName1))"
    $adsiSearcher1.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject1 = $adsiSearcher1.FindOne()
    
    # BdActr18: Set Owner
    $badAct0rSamAccountName2 = "BdActr" + $adDomainNetBIOS + "18"
    $adsiSearcher2 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName2))"
    $adsiSearcher2.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject2 = $adsiSearcher2.FindOne()
    
    # BdActr19: Write DACL
    $badAct0rSamAccountName3 = "BdActr" + $adDomainNetBIOS + "19"
    $adsiSearcher3 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName3))"
    $adsiSearcher3.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject3 = $adsiSearcher3.FindOne()
    
    # BdActr20: Write Owner
    $badAct0rSamAccountName4 = "BdActr" + $adDomainNetBIOS + "20"
    $adsiSearcher4 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName4))"
    $adsiSearcher4.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject4 = $adsiSearcher4.FindOne()
    
    # BdActr21: Full Control
    $badAct0rSamAccountName5 = "BdActr" + $adDomainNetBIOS + "21"
    $adsiSearcher5 = [adsisearcher]"(&(objectCategory=Person)(objectClass=user)(sAMAccountName=$badAct0rSamAccountName5))"
    $adsiSearcher5.SearchRoot = [ADSI]"LDAP://$adDomainRwdcPdcFsmoFQDN/$adDomainDN"
    $badAct0rObject5 = $adsiSearcher5.FindOne()
    
    Write-Host "Object DN: $adDomainDN" -ForegroundColor Magenta
    
    # Replicate Changes All
    Try {
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        Write-Host " > Bad Act0r: $($badAct0rObject1.Properties.samaccountname[0])" -ForegroundColor Cyan
        $badAct0rSidStringFormat1 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject1.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier1 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat1
        $badAct0rIdentityReference1 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier1
        $aceRight1 = [System.DirectoryServices.ActiveDirectoryRights] "ExtendedRight"
        $aceType1 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType1 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
        $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference1,$aceRight1,$aceType1,$schemaIDGUIDScopedCAR,$aceInheritanceType1
        $domain.psbase.objectSecurity.AddAccessRule($ace1)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Replicate Changes All On Domain NC..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Set Owner
    Try {
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        Write-Host " > Bad Act0r: $($badAct0rObject2.Properties.samaccountname[0])" -ForegroundColor Cyan
        $badAct0rSidStringFormat2 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject2.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier2 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat2
        $badAct0rIdentityReference2 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier2
        $domain.psbase.objectSecurity.SetOwner($badAct0rIdentityReference2)
        $domain.psbase.commitchanges()
        Write-Host " > Set As Owner Of Domain NC..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Write DACL
    Try {
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        Write-Host " > Bad Act0r: $($badAct0rObject3.Properties.samaccountname[0])" -ForegroundColor Cyan
        $badAct0rSidStringFormat3 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject3.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier3 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat3
        $badAct0rIdentityReference3 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier3
        $aceRight3 = [System.DirectoryServices.ActiveDirectoryRights] "WriteDACL"
        $aceType3 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType3 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
        $ace3 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference3,$aceRight3,$aceType3,$aceInheritanceType3
        $domain.psbase.objectSecurity.AddAccessRule($ace3)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Write DACL On Domain NC..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Write Owner
    Try {
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        Write-Host " > Bad Act0r: $($badAct0rObject4.Properties.samaccountname[0])" -ForegroundColor Cyan
        $badAct0rSidStringFormat4 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject4.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier4 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat4
        $badAct0rIdentityReference4 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier4
        $aceRight4 = [System.DirectoryServices.ActiveDirectoryRights] "WriteOwner"
        $aceType4 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType4 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
        $ace4 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference4,$aceRight4,$aceType4,$aceInheritanceType4
        $domain.psbase.objectSecurity.AddAccessRule($ace4)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Write Owner On Domain NC..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    # Full Control
    Try {
        $domain = [ADSI]("LDAP://" + $adDomainRwdcPdcFsmoFQDN + "/" + $adDomainDN)
        Write-Host " > Bad Act0r: $($badAct0rObject5.Properties.samaccountname[0])" -ForegroundColor Cyan
        $badAct0rSidStringFormat5 = (New-Object System.Security.Principal.SecurityIdentifier($($badAct0rObject5.Properties.objectsid),0)).Value
        $badAct0rSecurityIdentifier5 = [System.Security.Principal.SecurityIdentifier] $badAct0rSidStringFormat5
        $badAct0rIdentityReference5 = [System.Security.Principal.IdentityReference] $badAct0rSecurityIdentifier5
        $aceRight5 = [System.DirectoryServices.ActiveDirectoryRights] "GenericAll"
        $aceType5 = [System.Security.AccessControl.AccessControlType] "Allow"
        $aceInheritanceType5 = [System.DirectoryServices.ActiveDirectorySecurityInheritance] "None"
        $ace5 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule $badAct0rIdentityReference5,$aceRight5,$aceType5,$aceInheritanceType5
        $domain.psbase.objectSecurity.AddAccessRule($ace5)
        $domain.psbase.commitchanges()
        Write-Host " > Assigned Full Control On Domain NC..." -ForegroundColor Green
    } Catch {
        Write-Host " > Oops, Something Went Wrong..." -ForegroundColor Red
        Write-Host "Exception Message...: $($_.Exception.Message)" -ForegroundColor Red
    }
    Write-Host ""
    
    Write-Host "Module 03 completed" -ForegroundColor Green
    Write-Host ""
    return $true
}

Export-ModuleMember -Function Invoke-ModuleADDelegations