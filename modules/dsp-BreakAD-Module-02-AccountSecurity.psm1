################################################################################
# DSP Break AD - Module 02: Account Security
# 
# Purpose: Introduce account security misconfigurations to lower DSP score
# Targets: Account Security IOE category in DSP
#
# Author: Bob Lyons (bob@semperis.com)
# Modified: DSP Scoring Optimization
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
            # Get AD Forest and Domain Info
            $ADForest = Get-ADForest
            $ADDomain = Get-ADDomain
            $ADRootDomain = Get-ADForest | Select-Object -ExpandProperty RootDomain
            
            Write-Log "Forest: $($ADForest.Name) | Domain: $($ADDomain.Name)" -Level INFO

            # IOE 1: Use Built-in Administrator Account (Recent Activity)
            If ($Environment.Config.AccountSecurity_UseBuiltInAdmin -eq $true) {
                Write-Log "Enabling IOE: Built-in domain Administrator account used within last two weeks" -Level INFO
                
                Try {
                    $AdminAccount = Get-ADUser -Filter {SamAccountName -eq 'Administrator'} -Properties LastLogonDate
                    
                    If ($AdminAccount) {
                        $TempPassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$(Get-Random -Minimum 100000 -Maximum 999999)")
                        Set-ADAccountPassword -Identity $AdminAccount -NewPassword $TempPassword -Reset
                        
                        Write-Log "PASS: Built-in Administrator password reset to trigger recent activity" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: Error resetting Administrator password: $_" -Level ERROR
                }
            }

            # IOE 2: Administrator Account with Old Password (180+ days)
            If ($Environment.Config.AccountSecurity_AdminOldPassword -eq $true) {
                Write-Log "Enabling IOE: Built-in domain Administrator account with old password (180 days)" -Level INFO
                
                Try {
                    $AdminAccount = Get-ADUser -Filter {SamAccountName -eq 'Administrator'} -Properties pwdLastSet
                    
                    If ($AdminAccount) {
                        $DaysAgo = 185
                        $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                        $filetime = $TargetDate.ToFileTime()
                        
                        Set-ADUser -Identity $AdminAccount -Replace @{pwdLastSet = $filetime}
                        
                        Write-Log "PASS: Administrator pwdLastSet set to $DaysAgo days ago" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: Error setting old password date: $_" -Level ERROR
                }
            }

            # IOE 3: Privileged Accounts with Password Never Expires
            If ($Environment.Config.AccountSecurity_PrivilegedPwdNeverExpires -eq $true) {
                Write-Log "Enabling IOE: Privileged accounts with password that never expires" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 3; $i++) {
                        $UserName = "break-privacct-pwdneverexp-$i"
                        $UserDisplay = "Break: Priv Account Pwd Never Expires $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true `
                                -PasswordNotRequired $false
                            
                            Set-ADUser -Identity $UserName -PasswordNeverExpires $true
                            
                            Add-ADGroupMember -Identity "Domain Admins" -Members $UserName -ErrorAction SilentlyContinue
                            
                            Write-Log "PASS: Created privileged account $UserName with password never expires" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating privileged accounts with pwd never expires: $_" -Level ERROR
                }
            }

            # IOE 4: User Accounts with Reversible Encryption
            If ($Environment.Config.AccountSecurity_ReversibleEncryption -eq $true) {
                Write-Log "Enabling IOE: User accounts that store passwords with reversible encryption" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-revenc-$i"
                        $UserDisplay = "Break: Reversible Encryption $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Set-ADUser -Identity $UserName -Replace @{
                                'userAccountControl' = (([int]$(Get-ADUser $UserName -Properties userAccountControl).userAccountControl) -bor 128)
                            }
                            
                            Write-Log "PASS: Created user $UserName with reversible encryption enabled" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating reversible encryption accounts: $_" -Level ERROR
                }
            }

            # IOE 5: User Accounts with DES Encryption
            If ($Environment.Config.AccountSecurity_DESEncryption -eq $true) {
                Write-Log "Enabling IOE: User accounts that use DES encryption" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-des-$i"
                        $UserDisplay = "Break: DES Encryption $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Set-ADUser -Identity $UserName -Replace @{
                                'msDS-SupportedEncryptionTypes' = 1
                            }
                            
                            Write-Log "PASS: Created user $UserName with DES encryption only" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating DES encryption accounts: $_" -Level ERROR
                }
            }

            # IOE 6: User Accounts with Password Not Required
            If ($Environment.Config.AccountSecurity_PwdNotRequired -eq $true) {
                Write-Log "Enabling IOE: User accounts with password not required" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-nopwd-$i"
                        $UserDisplay = "Break: Password Not Required $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -Enabled $true `
                                -PasswordNotRequired $true
                            
                            Write-Log "PASS: Created user $UserName with password not required" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating password not required accounts: $_" -Level ERROR
                }
            }

            # IOE 7: Users with Kerberos Pre-authentication Disabled
            If ($Environment.Config.AccountSecurity_PreAuthDisabled -eq $true) {
                Write-Log "Enabling IOE: Users with Kerberos pre-authentication disabled" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-nopreauth-$i"
                        $UserDisplay = "Break: Pre-Auth Disabled $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Set-ADUser -Identity $UserName -Replace @{
                                'userAccountControl' = (([int]$(Get-ADUser $UserName -Properties userAccountControl).userAccountControl) -bor 4194304)
                            }
                            
                            Write-Log "PASS: Created user $UserName with pre-authentication disabled" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating pre-auth disabled accounts: $_" -Level ERROR
                }
            }

            # IOE 8: Unprivileged Accounts with adminCount=1
            If ($Environment.Config.AccountSecurity_UnprivilegedAdminCount -eq $true) {
                Write-Log "Enabling IOE: Unprivileged accounts with adminCount=1" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-admincnt-unprivileged-$i"
                        $UserDisplay = "Break: AdminCount Unprivileged $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Set-ADUser -Identity $UserName -Replace @{
                                'adminCount' = 1
                            }
                            
                            Write-Log "PASS: Created unprivileged user $UserName with adminCount=1" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating unprivileged adminCount accounts: $_" -Level ERROR
                }
            }

            # IOE 9: Accounts with Old Passwords (90+ days)
            If ($Environment.Config.AccountSecurity_OldPasswords -eq $true) {
                Write-Log "Enabling IOE: User accounts with old passwords (90+ days)" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-oldpwd-$i"
                        $UserDisplay = "Break: Old Password $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -Properties pwdLastSet -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            $DaysAgo = 95
                            $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                            $filetime = $TargetDate.ToFileTime()
                            
                            Set-ADUser -Identity $UserName -Replace @{pwdLastSet = $filetime}
                            
                            Write-Log "PASS: Created user $UserName with password last set $DaysAgo days ago" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating old password accounts: $_" -Level ERROR
                }
            }

            # IOE 10: Privileged Users that are Disabled
            If ($Environment.Config.AccountSecurity_DisabledPrivilegedUsers -eq $true) {
                Write-Log "Enabling IOE: Privileged users that are disabled" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-disabled-priv-$i"
                        $UserDisplay = "Break: Disabled Privileged User $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Add-ADGroupMember -Identity "Domain Admins" -Members $UserName -ErrorAction SilentlyContinue
                            
                            Disable-ADAccount -Identity $UserName
                            
                            Write-Log "PASS: Created disabled privileged user $UserName" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating disabled privileged users: $_" -Level ERROR
                }
            }

            # IOE 11: Recent Privileged Account Creation
            If ($Environment.Config.AccountSecurity_RecentPrivilegedCreation -eq $true) {
                Write-Log "Enabling IOE: Recent privileged account creation activity" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-newpriv-$i"
                        $UserDisplay = "Break: New Privileged Account $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Add-ADGroupMember -Identity "Domain Admins" -Members $UserName -ErrorAction SilentlyContinue
                            Add-ADGroupMember -Identity "Schema Admins" -Members $UserName -ErrorAction SilentlyContinue
                            
                            Write-Log "PASS: Created new privileged account $UserName" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating recent privileged accounts: $_" -Level ERROR
                }
            }

            # IOE 12: Recent AD Object Creation (within 10 days)
            If ($Environment.Config.AccountSecurity_RecentObjectCreation -eq $true) {
                Write-Log "Enabling IOE: AD objects created within the last 10 days" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 3; $i++) {
                        $UserName = "break-newobj-$i"
                        $UserDisplay = "Break: New Object $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Write-Log "PASS: Created new AD object $UserName" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating new AD objects: $_" -Level ERROR
                }
            }

            # IOE 13: Smart Card Auth with Old Password
            If ($Environment.Config.AccountSecurity_SmartCardOldPassword -eq $true) {
                Write-Log "Enabling IOE: User accounts using Smart Card authentication with old password" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 1; $i++) {
                        $UserName = "break-smartcard-$i"
                        $UserDisplay = "Break: Smart Card Old Password $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            Set-ADUser -Identity $UserName -SmartcardLogonRequired $true
                            
                            $DaysAgo = 100
                            $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                            $filetime = $TargetDate.ToFileTime()
                            
                            Set-ADUser -Identity $UserName -Replace @{pwdLastSet = $filetime}
                            
                            Write-Log "PASS: Created smart card user $UserName with old password" -Level SUCCESS
                        }
                    }
                } Catch {
                    Write-Log "FAIL: Error creating smart card old password accounts: $_" -Level ERROR
                }
            }

            Write-Log "Successfully completed Module 2: Account Security" -Level SUCCESS

        } Catch {
            Write-Log "Fatal error in $FunctionName : $_" -Level ERROR
            throw
        }
    }

    End {
        Write-Log "Finished $FunctionName" -Level INFO
    }
}

Export-ModuleMember -Function Invoke-ModuleAccountSecurity