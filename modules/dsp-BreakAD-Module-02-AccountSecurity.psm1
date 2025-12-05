#################################################################################
# DSP Break AD - Module 02: Account Security
# 
# Purpose: Introduce account security misconfigurations to lower DSP score
# Targets: Account Security IOE category in DSP
#
# IOEs Targeted:
#  - Built-in domain Administrator account used within the last two weeks
#  - Built-in domain Administrator account with old password (180 days)
#  - Privileged accounts with a password that never expires
#  - Privileged users with weak password policy
#  - Recent privileged account creation activity
#  - User accounts that store passwords with reversible encryption
#  - User accounts that use DES encryption
#  - User accounts with password not required
#  - Users with Kerberos pre-authentication disabled
#  - Unprivileged accounts with adminCount=1
#  - User accounts using Smart Card authentication with old password
#  - Users with old passwords
#  - Users with Password Never Expires flag set
#  - Abnormal Password Refresh
#  - AD objects created within the last 10 days
#  - Privileged users that are disabled
#  - Admins with old passwords
#
# Author: Bob Lyons (bob@semperis.com)
# Modified: DSP Scoring Optimization
#################################################################################

Function Invoke-DSPBreakAD-Module-02-AccountSecurity {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Logging,
        
        [Parameter(Mandatory = $true)]
        [System.Collections.Hashtable]
        $Config
    )

    Begin {
        $FunctionName = $MyInvocation.MyCommand.Name
        $Logging.Log("Starting $FunctionName", 'INFO')
    }

    Process {
        Try {
            # Get AD Forest and Domain Info
            $ADForest = Get-ADForest
            $ADDomain = Get-ADDomain
            $ADRootDomain = Get-ADForest | Select-Object -ExpandProperty RootDomain
            
            $Logging.Log("Forest: $($ADForest.Name) | Domain: $($ADDomain.Name)", 'INFO')

            # =====================================================================
            # IOE 1: Use Built-in Administrator Account (Recent Activity)
            # =====================================================================
            If ($Config.AccountSecurity_UseBuiltInAdmin -eq $true) {
                $Logging.Log("Enabling IOE: Built-in domain Administrator account used within the last two weeks", 'INFO')
                
                Try {
                    # Get the built-in Administrator account
                    $AdminAccount = Get-ADUser -Filter {SamAccountName -eq 'Administrator'} -Properties LastLogonDate
                    
                    If ($AdminAccount) {
                        # Force a password change to trigger recent activity
                        $TempPassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$(Get-Random -Minimum 100000 -Maximum 999999)")
                        Set-ADAccountPassword -Identity $AdminAccount -NewPassword $TempPassword -Reset
                        
                        $Logging.Log("  ✓ Built-in Administrator password reset to trigger recent activity", 'SUCCESS')
                    }
                } Catch {
                    $Logging.Log("  ✗ Error resetting Administrator password: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 2: Administrator Account with Old Password (180+ days)
            # =====================================================================
            If ($Config.AccountSecurity_AdminOldPassword -eq $true) {
                $Logging.Log("Enabling IOE: Built-in domain Administrator account with old password (180 days)", 'INFO')
                
                Try {
                    # This requires manipulating pwdLastSet attribute
                    $AdminAccount = Get-ADUser -Filter {SamAccountName -eq 'Administrator'} -Properties pwdLastSet
                    
                    If ($AdminAccount) {
                        # Set pwdLastSet to 185 days ago
                        $DaysAgo = 185
                        $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                        $filetime = $TargetDate.ToFileTime()
                        
                        Set-ADUser -Identity $AdminAccount -Replace @{pwdLastSet = $filetime}
                        
                        $Logging.Log("  ✓ Administrator pwdLastSet set to ~$DaysAgo days ago", 'SUCCESS')
                    }
                } Catch {
                    $Logging.Log("  ✗ Error setting old password date: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 3: Privileged Accounts with Password Never Expires
            # =====================================================================
            If ($Config.AccountSecurity_PrivilegedPwdNeverExpires -eq $true) {
                $Logging.Log("Enabling IOE: Privileged accounts with password that never expires", 'INFO')
                
                Try {
                    # Create test privileged accounts with password never expires
                    $PrivilegedGroupsToTarget = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
                    
                    For ($i = 1; $i -le 3; $i++) {
                        $UserName = "break-privacct-pwdneverexp-$i"
                        $UserDisplay = "Break: Priv Account Pwd Never Expires $i"
                        
                        # Check if user exists
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true `
                                -PasswordNotRequired $false
                            
                            # Set password to never expire
                            Set-ADUser -Identity $UserName -PasswordNotRequired $false
                            $UserObj = Get-ADUser $UserName
                            Set-ADAccountPassword -Identity $UserObj -NewPassword $SecurePassword -Reset
                            
                            # Now set to never expire
                            Set-ADUser -Identity $UserName -PasswordNeverExpires $true
                            
                            # Add to Domain Admins
                            Add-ADGroupMember -Identity "Domain Admins" -Members $UserName -ErrorAction SilentlyContinue
                            
                            $Logging.Log("  ✓ Created privileged account '$UserName' with password never expires", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating privileged accounts with pwd never expires: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 4: User Accounts with Reversible Encryption
            # =====================================================================
            If ($Config.AccountSecurity_ReversibleEncryption -eq $true) {
                $Logging.Log("Enabling IOE: User accounts that store passwords with reversible encryption", 'INFO')
                
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
                            
                            # Enable reversible encryption for this account
                            Set-ADUser -Identity $UserName -Replace @{
                                'userAccountControl' = (([int]$(Get-ADUser $UserName -Properties userAccountControl).userAccountControl) -bor 128)
                            }
                            
                            $Logging.Log("  ✓ Created user '$UserName' with reversible encryption enabled", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating reversible encryption accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 5: User Accounts with DES Encryption
            # =====================================================================
            If ($Config.AccountSecurity_DESEncryption -eq $true) {
                $Logging.Log("Enabling IOE: User accounts that use DES encryption", 'INFO')
                
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
                            
                            # Set msDS-SupportedEncryptionTypes to DES only (1)
                            Set-ADUser -Identity $UserName -Replace @{
                                'msDS-SupportedEncryptionTypes' = 1  # DES-CBC-MD5 only
                            }
                            
                            $Logging.Log("  ✓ Created user '$UserName' with DES encryption only", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating DES encryption accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 6: User Accounts with Password Not Required
            # =====================================================================
            If ($Config.AccountSecurity_PwdNotRequired -eq $true) {
                $Logging.Log("Enabling IOE: User accounts with password not required", 'INFO')
                
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
                            
                            $Logging.Log("  ✓ Created user '$UserName' with password not required", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating password not required accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 7: Users with Kerberos Pre-authentication Disabled
            # =====================================================================
            If ($Config.AccountSecurity_PreAuthDisabled -eq $true) {
                $Logging.Log("Enabling IOE: Users with Kerberos pre-authentication disabled", 'INFO')
                
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
                            
                            # Disable pre-authentication (UF_DONT_REQUIRE_PREAUTH = 0x400000 / 4194304)
                            Set-ADUser -Identity $UserName -Replace @{
                                'userAccountControl' = (([int]$(Get-ADUser $UserName -Properties userAccountControl).userAccountControl) -bor 4194304)
                            }
                            
                            $Logging.Log("  ✓ Created user '$UserName' with pre-authentication disabled", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating pre-auth disabled accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 8: Unprivileged Accounts with adminCount=1
            # =====================================================================
            If ($Config.AccountSecurity_UnprivilegedAdminCount -eq $true) {
                $Logging.Log("Enabling IOE: Unprivileged accounts with adminCount=1", 'INFO')
                
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
                            
                            # Set adminCount to 1 on unprivileged account
                            Set-ADUser -Identity $UserName -Replace @{
                                'adminCount' = 1
                            }
                            
                            $Logging.Log("  ✓ Created unprivileged user '$UserName' with adminCount=1", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating unprivileged adminCount accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 9: Accounts with Old Passwords (90+ days)
            # =====================================================================
            If ($Config.AccountSecurity_OldPasswords -eq $true) {
                $Logging.Log("Enabling IOE: User accounts with old passwords (90+ days)", 'INFO')
                
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
                            
                            # Set pwdLastSet to 95 days ago
                            $DaysAgo = 95
                            $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                            $filetime = $TargetDate.ToFileTime()
                            
                            Set-ADUser -Identity $UserName -Replace @{pwdLastSet = $filetime}
                            
                            $Logging.Log("  ✓ Created user '$UserName' with password last set ~$DaysAgo days ago", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating old password accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 10: Privileged Users that are Disabled
            # =====================================================================
            If ($Config.AccountSecurity_DisabledPrivilegedUsers -eq $true) {
                $Logging.Log("Enabling IOE: Privileged users that are disabled", 'INFO')
                
                Try {
                    For ($i = 1; $i -le 2; $i++) {
                        $UserName = "break-disabled-priv-$i"
                        $UserDisplay = "Break: Disabled Privileged User $i"
                        
                        $ExistingUser = Get-ADUser -Filter {SamAccountName -eq $UserName} -ErrorAction SilentlyContinue
                        
                        If (-not $ExistingUser) {
                            $SecurePassword = ConvertTo-SecureString -AsPlainText -Force -String ("P@ssw0rd_$($UserName)_$(Get-Random)")
                            
                            # Create enabled first
                            New-ADUser -SamAccountName $UserName `
                                -Name $UserDisplay `
                                -DisplayName $UserDisplay `
                                -AccountPassword $SecurePassword `
                                -Enabled $true
                            
                            # Add to Domain Admins
                            Add-ADGroupMember -Identity "Domain Admins" -Members $UserName -ErrorAction SilentlyContinue
                            
                            # Then disable
                            Disable-ADAccount -Identity $UserName
                            
                            $Logging.Log("  ✓ Created disabled privileged user '$UserName'", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating disabled privileged users: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 11: Recent Privileged Account Creation
            # =====================================================================
            If ($Config.AccountSecurity_RecentPrivilegedCreation -eq $true) {
                $Logging.Log("Enabling IOE: Recent privileged account creation activity", 'INFO')
                
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
                            
                            # Add to multiple privileged groups (will be detected as recent creation)
                            Add-ADGroupMember -Identity "Domain Admins" -Members $UserName -ErrorAction SilentlyContinue
                            Add-ADGroupMember -Identity "Schema Admins" -Members $UserName -ErrorAction SilentlyContinue
                            
                            $Logging.Log("  ✓ Created new privileged account '$UserName'", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating recent privileged accounts: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 12: Recent AD Object Creation (within 10 days)
            # =====================================================================
            If ($Config.AccountSecurity_RecentObjectCreation -eq $true) {
                $Logging.Log("Enabling IOE: AD objects created within the last 10 days", 'INFO')
                
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
                            
                            $Logging.Log("  ✓ Created new AD object '$UserName'", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating new AD objects: $_", 'ERROR')
                }
            }

            # =====================================================================
            # IOE 13: Smart Card Auth with Old Password
            # =====================================================================
            If ($Config.AccountSecurity_SmartCardOldPassword -eq $true) {
                $Logging.Log("Enabling IOE: User accounts using Smart Card authentication with old password", 'INFO')
                
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
                            
                            # Set smartCardLogonRequired
                            Set-ADUser -Identity $UserName -SmartcardLogonRequired $true
                            
                            # Set password old (90+ days)
                            $DaysAgo = 100
                            $TargetDate = [datetime]::Now.AddDays(-$DaysAgo)
                            $filetime = $TargetDate.ToFileTime()
                            
                            Set-ADUser -Identity $UserName -Replace @{pwdLastSet = $filetime}
                            
                            $Logging.Log("  ✓ Created smart card user '$UserName' with old password", 'SUCCESS')
                        }
                    }
                } Catch {
                    $Logging.Log("  ✗ Error creating smart card old password accounts: $_", 'ERROR')
                }
            }

            $Logging.Log("Successfully completed Module 2: Account Security", 'SUCCESS')

        } Catch {
            $Logging.Log("Fatal error in $FunctionName : $_", 'ERROR')
            throw
        }
    }

    End {
        $Logging.Log("Finished $FunctionName", 'INFO')
    }
}

Export-ModuleMember -Function Invoke-DSPBreakAD-Module-02-AccountSecurity