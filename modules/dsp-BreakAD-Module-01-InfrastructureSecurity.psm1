################################################################################
##
## dsp-BreakAD-Module-01-InfrastructureSecurity.psm1 (REBUILT)
##
## Infrastructure Security Misconfigurations - Targeting AD Infrastructure IOEs
##
## Phases:
## 1: Enable dSHeuristics (Anonymous NSPI access)
## 2: Enable Print Spooler on DCs
## 3: Disable LDAP Signing on DCs
## 4: Disable SMB Signing on DCs
## 5: Enable SMBv1 on DCs
## 6: Add Anonymous to Pre-Windows 2000 Compatible Access
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 5.0.0 - Infrastructure IOEs rebuild
##
################################################################################

function Invoke-ModuleInfrastructureSecurity {
    <#
    .SYNOPSIS
        Applies infrastructure security misconfigurations targeting DSP IOEs
    
    .PARAMETER Environment
        Hashtable containing Domain, DomainController, and Config info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    Write-Log "" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Module 01: Infrastructure Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 0: CREATE ORGANIZATIONAL UNITS
    ################################################################################
    
    ################################################################################
    # PHASE 1: ENABLE dSHEURISTICS (ANONYMOUS NSPI)
    ################################################################################
    
    Write-Log "PHASE 1: Enable dSHeuristics (Anonymous NSPI Access)" -Level INFO
    
    if ($config['InfrastructureSecurity_EnabledSHeuristics'] -eq 'true') {
        Write-Log "  Modifying dSHeuristics..." -Level INFO
        
        try {
            $rootDSE = Get-ADRootDSE
            $configNC = $rootDSE.configurationNamingContext
            $directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            
            $ldapPath = "LDAP://$directoryServicePath"
            $directoryService = [ADSI]$ldapPath
            
            $currentdSH = $directoryService.dSHeuristics.Value
            Write-Log "    Current value: '$currentdSH'" -Level INFO
            
            # Use config value or default
            $targetdSH = $config['InfrastructureSecurity_dSHeuristicsValue']
            if ([string]::IsNullOrEmpty($targetdSH)) {
                $targetdSH = "00000001"
            }
            
            if ($currentdSH -ne $targetdSH) {
                $directoryService.Put("dSHeuristics", $targetdSH)
                $directoryService.SetInfo()
                Write-Log "    [+] dSHeuristics set to: '$targetdSH'" -Level SUCCESS
            }
            else {
                Write-Log "    [+] Already at target value" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] dSHeuristics modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 2: ENABLE PRINT SPOOLER ON DCS
    ################################################################################
    
    Write-Log "PHASE 2: Enable Print Spooler on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_EnablePrintSpooler'] -eq 'true') {
        Write-Log "  Enabling Print Spooler service..." -Level INFO
        
        try {
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dc in $domainControllers) {
                Write-Log "    Processing DC: $($dc.HostName)" -Level INFO
                
                try {
                    $spoolerService = Get-Service -Name Spooler -ComputerName $dc.HostName -ErrorAction SilentlyContinue
                    
                    if ($null -ne $spoolerService) {
                        if ($spoolerService.StartType -ne "Automatic") {
                            Set-Service -Name Spooler -StartupType Automatic -ComputerName $dc.HostName -ErrorAction Stop
                            Write-Log "      [+] Startup type set to Automatic" -Level SUCCESS
                        }
                        
                        if ($spoolerService.Status -ne "Running") {
                            Start-Service -Name Spooler -ComputerName $dc.HostName -ErrorAction Stop
                            Write-Log "      [+] Service started" -Level SUCCESS
                        }
                        else {
                            Write-Log "      [+] Service already running" -Level SUCCESS
                        }
                    }
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error accessing Domain Controllers: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Print Spooler modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 3: DISABLE LDAP SIGNING
    ################################################################################
    
    Write-Log "PHASE 3: Disable LDAP Signing on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_DisableLDAPSigning'] -eq 'true') {
        Write-Log "  Disabling LDAP Signing via registry..." -Level INFO
        
        try {
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dc in $domainControllers) {
                Write-Log "    Processing DC: $($dc.HostName)" -Level INFO
                
                try {
                    $regPath = "HKLM:\System\CurrentControlSet\Services\NTDS\Parameters"
                    $regValue = "LDAPServerIntegrity"
                    
                    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                        param($path, $name)
                        Set-ItemProperty -Path $path -Name $name -Value 0 -Force -ErrorAction Stop
                    } -ArgumentList $regPath, $regValue -ErrorAction Stop
                    
                    Write-Log "      [+] LDAP Signing disabled" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] LDAP Signing modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 4: DISABLE SMB SIGNING
    ################################################################################
    
    Write-Log "PHASE 4: Disable SMB Signing on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_DisableSMBSigning'] -eq 'true') {
        Write-Log "  Disabling SMB Signing via registry..." -Level INFO
        
        try {
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dc in $domainControllers) {
                Write-Log "    Processing DC: $($dc.HostName)" -Level INFO
                
                try {
                    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Value 0 -Force -ErrorAction Stop
                    } -ErrorAction Stop
                    
                    Write-Log "      [+] SMB Signing disabled" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] SMB Signing modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 5: ENABLE SMBv1
    ################################################################################
    
    Write-Log "PHASE 5: Enable SMBv1 on Domain Controllers" -Level INFO
    
    if ($config['InfrastructureSecurity_EnableSMBv1'] -eq 'true') {
        Write-Log "  Enabling SMBv1 via registry..." -Level INFO
        
        try {
            $domainControllers = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dc in $domainControllers) {
                Write-Log "    Processing DC: $($dc.HostName)" -Level INFO
                
                try {
                    Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
                        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Force -ErrorAction Stop
                    } -ErrorAction Stop
                    
                    Write-Log "      [+] SMBv1 enabled" -Level SUCCESS
                }
                catch {
                    Write-Log "      [!] Error: $_" -Level WARNING
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] SMBv1 modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # PHASE 6: ADD ANONYMOUS TO PRE-WINDOWS 2000 COMPATIBLE ACCESS
    ################################################################################
    
    Write-Log "PHASE 6: Add Anonymous to Pre-Windows 2000 Compatible Access" -Level INFO
    
    if ($config['InfrastructureSecurity_AddAnonymousPre2000'] -eq 'true') {
        Write-Log "  Adding Anonymous Logon to group..." -Level INFO
        
        try {
            $groupName = "Pre-Windows 2000 Compatible Access"
            $group = Get-ADGroup -Identity $groupName -ErrorAction Stop
            
            # Check if Anonymous is already a member
            $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
            $hasAnonymous = $members | Where-Object { $_.SID -eq "S-1-5-7" } -ErrorAction SilentlyContinue
            
            if ($null -eq $hasAnonymous) {
                # Use ADSI to add the well-known SID
                $groupADSI = [ADSI]"LDAP://$($group.DistinguishedName)"
                $groupADSI.Add("LDAP://<SID=S-1-5-7>")
                $groupADSI.SetInfo()
                
                Write-Log "    [+] Anonymous Logon added" -Level SUCCESS
            }
            else {
                Write-Log "    [+] Anonymous Logon already member" -Level SUCCESS
            }
        }
        catch {
            Write-Log "    [!] Error: $_" -Level WARNING
        }
    }
    else {
        Write-Log "  [*] Anonymous to Pre-2000 modification disabled in config" -Level INFO
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # COMPLETION
    ################################################################################
    
    Write-Log "========================================" -Level INFO
    Write-Log "Module 01: Infrastructure Security" -Level INFO
    Write-Log "========================================" -Level INFO
    Write-Log "Status: COMPLETE" -Level SUCCESS
    Write-Log "" -Level INFO
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity