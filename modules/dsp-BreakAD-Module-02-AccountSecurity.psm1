################################################################################
# DSP Break AD - Module 02: Account Security (IDEMPOTENT)
# 
# Purpose: Introduce account security misconfigurations to lower DSP score
# Targets: Account Security IOE category in DSP
# Note: This module is idempotent - safe to run multiple times
#
# Author: Bob Lyons (bob@semperis.com)
################################################################################

function Invoke-ModuleAccountSecurity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [hashtable]
        $Environment
    )

    Begin {
        $FunctionName = $MyInvocation.MyCommand.Name
        Write-Log "Starting $FunctionName" -Level INFO
    }

    Process {
        Try {
            $ADForest = Get-ADForest
            $ADDomain = Get-ADDomain
            
            Write-Log "Forest: $($ADForest.Name) | Domain: $($ADDomain.Name)" -Level INFO

            # Helper function to recreate account (idempotent)
            Function New-BreakAccount {
                Param(
                    [string]$SamAccountName,
                    [string]$DisplayName,
                    [string]$Password,
                    [bool]$Enabled = $true,
                    [bool]$PasswordNotRequired = $false,
                    [string[]]$GroupsToAdd = @()
                )
                
                $existing = Get-ADUser -Filter {SamAccountName -eq $SamAccountName} -ErrorAction SilentlyContinue
                if ($existing) {
                    Remove-ADUser -Identity $existing -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                }
                
                $securePassword = ConvertTo-SecureString -AsPlainText -Force -String $Password
                
                $user = New-ADUser -SamAccountName $SamAccountName `
                    -Name $DisplayName `
                    -DisplayName $DisplayName `
                    -AccountPassword $securePassword `
                    -Enabled $Enabled `
                    -PasswordNotRequired $PasswordNotRequired `
                    -PassThru -ErrorAction Stop
                
                foreach ($group in $GroupsToAdd) {
                    Add-ADGroupMember -Identity $group -Members $user -ErrorAction SilentlyContinue
                }
                
                return $user
            }

            # IOE 1: Use Built-in Administrator Account (Recent Activity)
            If ($Environment.Config.AccountSecurity_UseBuiltInAdmin -eq $true) {
                Write-Log "Enabling IOE: Built-in domain Administrator account used within last two weeks" -Level INFO
                
                Try {
                    $AdminAccount = Get-ADUser -Filter {SamAccountName -eq 'Administrator'}
                    $TempPassword = ConvertTo-SecureString -AsPlainText -Force -String "P@ssw0rd1234567890Admin"
                    Set-ADAccountPassword -Identity $AdminAccount -NewPassword $TempPassword -Reset
                    Write-Log "PASS: Built-in Administrator password reset" -Level SUCCESS
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 3: Privileged Accounts with Password Never Expires
            If ($Environment.Config.AccountSecurity_PrivilegedPwdNeverExpires -eq $true) {
                Write-Log "Enabling IOE: Privileged accounts with password that never expires" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 3; $i++) {
                        $user = New-BreakAccount -SamAccountName "brkprivpwdexp$i" `
                            -DisplayName "Break: Priv Account Pwd Never Expires $i" `
                            -Password "P@ssw0rd1234567890PrivExp$i" `
                            -GroupsToAdd @("Domain Admins")
                        
                        Set-ADUser -Identity $user -PasswordNeverExpires $true
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 4: User Accounts with Reversible Encryption
            If ($Environment.Config.AccountSecurity_ReversibleEncryption -eq $true) {
                Write-Log "Enabling IOE: User accounts with reversible encryption" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brkrevenc$i" `
                            -DisplayName "Break: Reversible Encryption $i" `
                            -Password "P@ssw0rd1234567890RevEnc$i"
                        
                        Set-ADUser -Identity $user -Replace @{'userAccountControl' = (([int]$(Get-ADUser $user -Properties userAccountControl).userAccountControl) -bor 128)}
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 5: User Accounts with DES Encryption
            If ($Environment.Config.AccountSecurity_DESEncryption -eq $true) {
                Write-Log "Enabling IOE: User accounts with DES encryption" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brkdes$i" `
                            -DisplayName "Break: DES Encryption $i" `
                            -Password "P@ssw0rd1234567890Des$i"
                        
                        Set-ADUser -Identity $user -Replace @{'msDS-SupportedEncryptionTypes' = 1}
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 6: User Accounts with Password Not Required
            If ($Environment.Config.AccountSecurity_PwdNotRequired -eq $true) {
                Write-Log "Enabling IOE: User accounts with password not required" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brknopwd$i" `
                            -DisplayName "Break: Password Not Required $i" `
                            -Password "P@ssw0rd1234567890NoPwd$i" `
                            -PasswordNotRequired $true
                        
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 7: Users with Kerberos Pre-authentication Disabled
            If ($Environment.Config.AccountSecurity_PreAuthDisabled -eq $true) {
                Write-Log "Enabling IOE: Users with pre-authentication disabled" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brknopreauth$i" `
                            -DisplayName "Break: Pre-Auth Disabled $i" `
                            -Password "P@ssw0rd1234567890PreAuth$i"
                        
                        Set-ADUser -Identity $user -Replace @{'userAccountControl' = (([int]$(Get-ADUser $user -Properties userAccountControl).userAccountControl) -bor 4194304)}
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 8: Unprivileged Accounts with adminCount=1
            If ($Environment.Config.AccountSecurity_UnprivilegedAdminCount -eq $true) {
                Write-Log "Enabling IOE: Unprivileged accounts with adminCount=1" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brkadmincnt$i" `
                            -DisplayName "Break: AdminCount Unprivileged $i" `
                            -Password "P@ssw0rd1234567890AdminCnt$i"
                        
                        Set-ADUser -Identity $user -Replace @{'adminCount' = 1}
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 9: Accounts with Old Passwords (90+ days)
            If ($Environment.Config.AccountSecurity_OldPasswords -eq $true) {
                Write-Log "Enabling IOE: User accounts with old passwords (90+ days)" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brkoldpwd$i" `
                            -DisplayName "Break: Old Password $i" `
                            -Password "P@ssw0rd1234567890OldPwd$i"
                        
                        $DaysAgo = 95
                        $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                        $filetime = $TargetDate.ToFileTime()
                        
                        $ldapPath = "LDAP://$($user.DistinguishedName)"
                        $adsiUser = [ADSI]$ldapPath
                        $adsiUser.Put("pwdLastSet", $filetime)
                        $adsiUser.SetInfo()
                        
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 10: Privileged Users that are Disabled
            If ($Environment.Config.AccountSecurity_DisabledPrivilegedUsers -eq $true) {
                Write-Log "Enabling IOE: Privileged users that are disabled" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brkdisabledpriv$i" `
                            -DisplayName "Break: Disabled Privileged User $i" `
                            -Password "P@ssw0rd1234567890DisPriv$i" `
                            -Enabled $true `
                            -GroupsToAdd @("Domain Admins")
                        
                        Disable-ADAccount -Identity $user
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 11: Recent Privileged Account Creation
            If ($Environment.Config.AccountSecurity_RecentPrivilegedCreation -eq $true) {
                Write-Log "Enabling IOE: Recent privileged account creation activity" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $user = New-BreakAccount -SamAccountName "brknewpriv$i" `
                            -DisplayName "Break: New Privileged Account $i" `
                            -Password "P@ssw0rd1234567890NewPriv$i" `
                            -GroupsToAdd @("Domain Admins", "Schema Admins")
                        
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 12: Recent AD Object Creation (within 10 days)
            If ($Environment.Config.AccountSecurity_RecentObjectCreation -eq $true) {
                Write-Log "Enabling IOE: AD objects created within 10 days" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 3; $i++) {
                        $user = New-BreakAccount -SamAccountName "brknewobj$i" `
                            -DisplayName "Break: New Object $i" `
                            -Password "P@ssw0rd1234567890NewObj$i"
                        
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 13: Smart Card Auth with Old Password
            If ($Environment.Config.AccountSecurity_SmartCardOldPassword -eq $true) {
                Write-Log "Enabling IOE: Smart Card with old password" -Level INFO
                
                Try {
                    $user = New-BreakAccount -SamAccountName "brksmartcard1" `
                        -DisplayName "Break: Smart Card Old Password" `
                        -Password "P@ssw0rd1234567890SmartCard1"
                    
                    Set-ADUser -Identity $user -SmartcardLogonRequired $true
                    
                    $DaysAgo = 100
                    $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                    $filetime = $TargetDate.ToFileTime()
                    
                    $ldapPath = "LDAP://$($user.DistinguishedName)"
                    $adsiUser = [ADSI]$ldapPath
                    $adsiUser.Put("pwdLastSet", $filetime)
                    $adsiUser.SetInfo()
                    
                    Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            Write-Log "Successfully completed Module 2: Account Security" -Level SUCCESS

        } Catch {
            Write-Log "Fatal error: $_" -Level ERROR
            throw
        }
    }

    End {
        Write-Log "Finished $FunctionName" -Level INFO
    }
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity