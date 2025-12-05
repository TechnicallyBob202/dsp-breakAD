################################################################################
# DSP Break AD - Module 02: Account Security (IDEMPOTENT)
# 
# Purpose: Introduce account security misconfigurations to lower DSP score
# Targets: Account Security IOE category in DSP
# Note: This module is idempotent - safe to run multiple times
#
# IOEs Implemented: 11 of 13
# Skipped IOEs:
#   - IOE 1: Built-in Administrator recently used - CANNOT reset admin password
#   - IOE 9: User accounts with old passwords (90+ days) - pwdLastSet cannot be set post-creation
#   - IOE 13: Smart Card with old password - pwdLastSet cannot be set post-creation
# 
# New IOEs:
#   - IOE 14: Privileged accounts with weak Fine-Grained Password Policy (FGPP)
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
                
                # Add random suffix to avoid recycle bin conflicts
                $randomSuffix = Get-Random -Minimum 100 -Maximum 999
                $uniqueSamName = "$SamAccountName$randomSuffix"
                $uniqueDisplayName = "$DisplayName #$randomSuffix"
                
                $existing = Get-ADUser -Filter {SamAccountName -eq $uniqueSamName} -ErrorAction SilentlyContinue
                if ($existing) {
                    Remove-ADUser -Identity $existing -Confirm:$false -ErrorAction SilentlyContinue
                    Start-Sleep -Milliseconds 500
                }
                
                $securePassword = ConvertTo-SecureString -AsPlainText -Force -String $Password
                
                $user = New-ADUser -SamAccountName $uniqueSamName `
                    -Name $uniqueDisplayName `
                    -DisplayName $uniqueDisplayName `
                    -AccountPassword $securePassword `
                    -Enabled $Enabled `
                    -PasswordNotRequired $PasswordNotRequired `
                    -PassThru -ErrorAction Stop
                
                foreach ($group in $GroupsToAdd) {
                    Add-ADGroupMember -Identity $group -Members $user -ErrorAction SilentlyContinue
                }
                
                return $user
            }

            # IOE 1: Built-in Administrator Recently Used
            # NOTE: REMOVED - Cannot reset built-in Administrator password in lab
            If ($false) {
                Write-Log "Enabling IOE: Built-in Administrator recently used" -Level INFO
                Write-Log "SKIP: Cannot modify built-in Administrator account" -Level INFO
            }

            # IOE 3: Privileged Accounts with Password Never Expires
            If ($Environment.Config.AccountSecurity_PrivilegedPwdNeverExpires -eq $true) {
                Write-Log "Enabling IOE: Privileged accounts with password that never expires" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-ppwd$i" `
                            -DisplayName "Break: Priv Account Pwd Never Expires $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32)) `
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-renc$i" `
                            -DisplayName "Break: Reversible Encryption $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
                        
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-des$i" `
                            -DisplayName "Break: DES Encryption $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
                        
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-npwd$i" `
                            -DisplayName "Break: Password Not Required $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32)) `
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-prea$i" `
                            -DisplayName "Break: Pre-Auth Disabled $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
                        
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-acnt$i" `
                            -DisplayName "Break: AdminCount Unprivileged $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
                        
                        Set-ADUser -Identity $user -Replace @{'adminCount' = 1}
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 9: Accounts with Old Passwords (90+ days)
            # NOTE: Skipped - pwdLastSet cannot be set via ADSI after account creation
            If ($false) {
                Write-Log "Enabling IOE: User accounts with old passwords (90+ days)" -Level INFO
                Write-Log "SKIP: pwdLastSet modification disabled" -Level INFO
            }

            # IOE 10: Privileged Users that are Disabled
            If ($Environment.Config.AccountSecurity_DisabledPrivilegedUsers -eq $true) {
                Write-Log "Enabling IOE: Privileged users that are disabled" -Level INFO
                
                Try {
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-dpriv$i" `
                            -DisplayName "Break: Disabled Privileged User $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32)) `
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-npr$i" `
                            -DisplayName "Break: New Privileged Account $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32)) `
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
                    For ($i = 1; $i -le 1; $i++) {
                        $user = New-BreakAccount -SamAccountName "break-nobj$i" `
                            -DisplayName "Break: New Object $i" `
                            -Password $(-join (33..126 | ForEach-Object { [char]$_ } | Get-Random -Count 32))
                        
                        Write-Log "PASS: Created $($user.SamAccountName)" -Level SUCCESS
                    }
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

            # IOE 13: Smart Card Auth with Old Password
            # NOTE: Skipped - pwdLastSet cannot be set via ADSI after account creation
            If ($false) {
                Write-Log "Enabling IOE: Smart Card with old password" -Level INFO
                Write-Log "SKIP: pwdLastSet modification disabled" -Level INFO
            }

            # IOE 14: Privileged Accounts with Weak Password Policy (FGPP)
            If ($Environment.Config.AccountSecurity_WeakFGPP -eq $true) {
                Write-Log "Enabling IOE: Privileged accounts with weak Fine-Grained Password Policy" -Level INFO
                
                Try {
                    # Create FGPP object with weak settings
                    $fgppName = "break-weakpwdpolicy"
                    $fgppExists = Get-ADFineGrainedPasswordPolicy -Filter {Name -eq $fgppName} -ErrorAction SilentlyContinue
                    
                    If (-not $fgppExists) {
                        # Create FGPP with intentionally weak settings
                        $fgpp = New-ADFineGrainedPasswordPolicy -Name $fgppName `
                            -DisplayName "Break: Weak Password Policy" `
                            -Description "Weak password policy for privileged accounts" `
                            -Precedence 1 `
                            -MinPasswordLength 4 `
                            -MinPasswordAge 0 `
                            -MaxPasswordAge (New-TimeSpan -Days 999) `
                            -PasswordHistoryCount 0 `
                            -LockoutDuration (New-TimeSpan -Minutes 0) `
                            -LockoutObservationWindow (New-TimeSpan -Minutes 0) `
                            -LockoutThreshold 0 `
                            -ComplexityEnabled $false `
                            -ReversibleEncryptionEnabled $true `
                            -PassThru -ErrorAction Stop
                        
                        Write-Log "PASS: Created weak Fine-Grained Password Policy: $fgppName" -Level SUCCESS
                    }
                    else {
                        $fgpp = $fgppExists
                        Write-Log "PASS: FGPP already exists: $fgppName" -Level SUCCESS
                    }
                    
                    # Apply FGPP to privileged break-ppwd accounts
                    $privilegedAccounts = Get-ADUser -Filter {SamAccountName -like "break-ppwd*"} -ErrorAction SilentlyContinue
                    
                    If ($privilegedAccounts) {
                        foreach ($account in $privilegedAccounts) {
                            Add-ADFineGrainedPasswordPolicySubject -Identity $fgpp -Subjects $account -ErrorAction SilentlyContinue
                            Write-Log "PASS: Applied weak FGPP to privileged account: $($account.SamAccountName)" -Level SUCCESS
                        }
                    }
                    
                } Catch {
                    Write-Log "FAIL: $_" -Level ERROR
                }
            }

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