################################################################################
##
## dsp-BreakAD-Module-01-InfrastructureSecurity.psm1
##
## Configures infrastructure security misconfigurations
## - Enable print spooler on DCs
## - Add users to privileged groups (Schema Admins, Enterprise Admins)
## - Modify dSHeuristics for dangerous settings
## - Weaken AdminSDHolder protection
##
## Author: Bob Lyons (bob@semperis.com)
## Version: 1.0.0
##
################################################################################

function Invoke-ModuleInfrastructureSecurity {
    <#
    .SYNOPSIS
        Applies infrastructure security misconfigurations
    
    .PARAMETER Environment
        Hashtable containing Domain and DomainController info
    #>
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Environment
    )
    
    $domain = $Environment.Domain
    $dc = $Environment.DomainController
    $config = $Environment.Config
    
    $successCount = 0
    $errorCount = 0
    
    Write-Log "Infrastructure Security Module Starting" -Level INFO
    Write-Log "Domain: $($domain.Name)" -Level INFO
    Write-Log "DC: $($dc.HostName)" -Level INFO
    Write-Log "" -Level INFO
    
    ################################################################################
    # PRINT SPOOLER
    ################################################################################
    
    if ($config['InfrastructureSecurity_EnablePrintSpooler'] -eq 'true') {
        Write-Log "Enabling Print Spooler on Domain Controllers..." -Level INFO
        
        try {
            $dcs = Get-ADDomainController -Filter * -ErrorAction Stop
            
            foreach ($dcItem in $dcs) {
                try {
                    Write-Log "  Targeting: $($dcItem.HostName)" -Level INFO
                    
                    $spoolerService = Get-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
                    
                    if ($spoolerService.StartType -ne "Automatic") {
                        Set-Service -Name Spooler -ComputerName $dcItem.HostName -StartupType Automatic -ErrorAction Stop
                        Write-LogChange -Object $dcItem.HostName -Attribute "Spooler StartupType" -OldValue $spoolerService.StartType -NewValue "Automatic"
                    }
                    
                    if ($spoolerService.Status -ne "Running") {
                        Start-Service -Name Spooler -ComputerName $dcItem.HostName -ErrorAction Stop
                        Write-LogChange -Object $dcItem.HostName -Attribute "Spooler Status" -OldValue "Stopped" -NewValue "Running"
                    }
                    
                    Write-Log "    [+] Print Spooler enabled" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error on $($dcItem.HostName): $_" -Level WARNING
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error enumerating DCs: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # SCHEMA ADMINS GROUP
    ################################################################################
    
    $schemaAdminsCount = [int]$config['InfrastructureSecurity_AddToSchemaAdmins']
    if ($schemaAdminsCount -gt 0) {
        Write-Log "Adding $schemaAdminsCount users to Schema Admins group..." -Level INFO
        
        try {
            $schemaAdminsGroup = Get-ADGroup -Identity "Schema Admins" -ErrorAction Stop
            $domainDN = $domain.DistinguishedName
            
            for ($i = 1; $i -le $schemaAdminsCount; $i++) {
                $userName = "break-SchemaAdmin-$i"
                $userDN = "CN=$userName,CN=Users,$domainDN"
                
                Write-Log "  Processing: $userName" -Level INFO
                
                try {
                    # Create user if doesn't exist
                    $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
                    if (-not $existingUser) {
                        Write-Log "    User does not exist, creating..." -Level INFO
                        try {
                            New-ADUser `
                                -Name $userName `
                                -SamAccountName $userName `
                                -AccountPassword (ConvertTo-SecureString "P@ssw0rd!$i" -AsPlainText -Force) `
                                -Enabled $true `
                                -ErrorAction Stop
                            Write-Log "  [+] Created user: $userName" -Level SUCCESS
                        }
                        catch {
                            Write-Log "    [!] Failed to create user $userName : $_" -Level WARNING
                            throw $_
                        }
                        
                        # Wait for replication and AD to catch up
                        Start-Sleep -Seconds 2
                    }
                    else {
                        Write-Log "  [*] User already exists: $userName" -Level INFO
                    }
                    
                    # Verify user exists before adding to group
                    $user = $null
                    for ($retry = 0; $retry -lt 5; $retry++) {
                        $user = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
                        if ($user) {
                            Write-Log "    [*] Found user on attempt $($retry + 1)" -Level INFO
                            break
                        }
                        Start-Sleep -Milliseconds 500
                    }
                    
                    if (-not $user) {
                        throw "User $userName not found after creation (tried 5 times)"
                    }
                    
                    Add-ADGroupMember -Identity $schemaAdminsGroup -Members $user -ErrorAction SilentlyContinue
                    Write-LogChange -Object $userName -Attribute "Group Membership" -OldValue "N/A" -NewValue "Schema Admins"
                    Write-Log "  [+] Added to Schema Admins: $userName" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "  [!] Error with $userName : $_" -Level WARNING
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # ENTERPRISE ADMINS GROUP
    ################################################################################
    
    $enterpriseAdminsCount = [int]$config['InfrastructureSecurity_AddToEnterpriseAdmins']
    if ($enterpriseAdminsCount -gt 0) {
        Write-Log "Adding $enterpriseAdminsCount users to Enterprise Admins group..." -Level INFO
        
        try {
            $enterpriseAdminsGroup = Get-ADGroup -Identity "Enterprise Admins" -ErrorAction Stop
            $domainDN = $domain.DistinguishedName
            
            for ($i = 1; $i -le $enterpriseAdminsCount; $i++) {
                $userName = "break-EnterpriseAdmin-$i"
                
                try {
                    # Create user if doesn't exist
                    $existingUser = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
                    if (-not $existingUser) {
                        New-ADUser `
                            -Name $userName `
                            -SamAccountName $userName `
                            -AccountPassword (ConvertTo-SecureString "P@ssw0rd!$i" -AsPlainText -Force) `
                            -Enabled $true `
                            -ErrorAction Stop
                        Write-Log "  [+] Created user: $userName" -Level SUCCESS
                        
                        # Wait for replication and AD to catch up
                        Start-Sleep -Seconds 2
                    }
                    else {
                        Write-Log "  [*] User already exists: $userName" -Level INFO
                    }
                    
                    # Verify user exists before adding to group
                    $user = $null
                    for ($retry = 0; $retry -lt 5; $retry++) {
                        $user = Get-ADUser -Identity $userName -ErrorAction SilentlyContinue
                        if ($user) {
                            break
                        }
                        Start-Sleep -Milliseconds 500
                    }
                    
                    if (-not $user) {
                        throw "User $userName not found after creation"
                    }
                    
                    Add-ADGroupMember -Identity $enterpriseAdminsGroup -Members $user -ErrorAction SilentlyContinue
                    Write-LogChange -Object $userName -Attribute "Group Membership" -OldValue "N/A" -NewValue "Enterprise Admins"
                    Write-Log "  [+] Added to Enterprise Admins: $userName" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "  [!] Error with $userName : $_" -Level WARNING
                    $errorCount++
                }
            }
        }
        catch {
            Write-Log "  [!] Error: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # dSHEURISTICS MODIFICATIONS
    ################################################################################
    
    if ($config['InfrastructureSecurity_ModifydSHeuristics'] -eq 'true') {
        Write-Log "Modifying dSHeuristics for dangerous settings..." -Level INFO
        
        try {
            # Build configuration naming context from domain DN
            # DC=d3,DC=lab -> CN=Configuration,DC=d3,DC=lab
            $domainDNParts = $domainDN -split ','
            $configNC = "CN=Configuration," + ($domainDNParts -join ',')
            $directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"
            
            Write-Log "  Directory Service Path: $directoryServicePath" -Level INFO
            
            # Use LDAP to get and set dSHeuristics (more reliable than Set-ADObject)
            $ldapPath = "LDAP://$directoryServicePath"
            $directoryService = [ADSI]$ldapPath
            $currentdSH = $directoryService.dSHeuristics
            
            Write-Log "  Current dSHeuristics: '$currentdSH'" -Level INFO
            
            # Enable anonymous NSPI (position 7 = 1)
            # This is a realistic misconfiguration that DSP detects
            $newdSH = "00000001"
            
            if ($newdSH -ne $currentdSH) {
                try {
                    $directoryService.Put("dSHeuristics", $newdSH)
                    $directoryService.SetInfo()
                    
                    Write-LogChange -Object "Directory Service" -Attribute "dSHeuristics" -OldValue $currentdSH -NewValue $newdSH
                    Write-Log "  [+] dSHeuristics modified: '$newdSH'" -Level SUCCESS
                    $successCount++
                }
                catch {
                    Write-Log "    [!] Error setting dSHeuristics: $_" -Level WARNING
                    $errorCount++
                }
            }
            else {
                Write-Log "  [*] dSHeuristics already at target value" -Level INFO
            }
        }
        catch {
            Write-Log "  [!] Error modifying dSHeuristics: $_" -Level WARNING
            $errorCount++
        }
    }
    
    Write-Log "" -Level INFO
    
    ################################################################################
    # SUMMARY
    ################################################################################
    
    Write-Log "Infrastructure Security Module Complete" -Level INFO
    Write-Log "Successful changes: $successCount" -Level SUCCESS
    if ($errorCount -gt 0) {
        Write-Log "Errors encountered: $errorCount" -Level WARNING
        return $false
    }
    
    return $true
}

Export-ModuleMember -Function Invoke-ModuleInfrastructureSecurity