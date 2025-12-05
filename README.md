# dsp-breakAD - AD Security Misconfiguration Simulation Tool

A PowerShell-based utility to deliberately introduce realistic security misconfigurations into a lab Active Directory environment for DSP (Directory Services Protector) demonstration and testing.

**Author:** Bob Lyons (bob@semperis.com)  
**Status:** Infrastructure Security Module (01) - Production Ready

## Overview

dsp-breakAD allows you to systematically introduce AD security misconfigurations that mirror real-world poorly-configured environments. Each module targets a specific DSP Infrastructure Security IOE and can be run independently or in sequence.

The tool is designed to weaken AD security realistically without breaking it - all changes are intentional, logged, and documented for reversal.

## Prerequisites

- PowerShell 5.1 or higher
- Administrator rights on domain-joined machine
- Active Directory PowerShell module
- Group Policy Management module (for GPO-based changes)
- Connection to at least one Domain Controller
- **Lab/test AD forest (NOT production)**

## Quick Start

### Run with Default Settings (Preflight + Module 01)
```powershell
.\dsp-breakAD.ps1 -All
```

### Run Specific Module
```powershell
.\dsp-breakAD.ps1 -ModuleNames "InfrastructureSecurity"
```

### Interactive Selection
```powershell
.\dsp-breakAD.ps1
```

### Skip Preflight Validation
```powershell
.\dsp-breakAD.ps1 -All -SkipPreflight
```

## Structure

```
dsp-breakAD/
├── dsp-breakAD.ps1                                  # Main orchestration script
├── dsp-breakAD.config                               # Module configuration
├── dsp-BreakAD-Logging.psm1                         # Logging functionality
├── dsp-BreakAD-Module-00-Preflight.psm1             # Environment validation
├── dsp-BreakAD-Module-01-InfrastructureSecurity-Rebuilt.psm1
├── PROJECT_NOTES.md                                 # Detailed project notes
├── logs/                                            # Auto-created execution logs
└── modules/                                         # Future modules (02-05)
```

## Execution Flow

1. **Load Configuration** - Read dsp-breakAD.config
2. **Run Preflight** - Validate environment, create OUs, discover domain/DC
3. **Module Selection** - User selects which modules to run
4. **Load Modules** - Import selected PowerShell modules
5. **Execute Modules** - Run each module with environment context
6. **Log Results** - Write detailed logs to logs/ directory

## Module: Infrastructure Security (Module 01)

**Target Category:** AD Infrastructure Security IOEs  
**Phases:** 9  
**Config File:** dsp-breakAD.config

**Skipped IOEs:**
- "Well-known privileged SIDs in sIDHistory" - Requires migration privileges not available in standard lab
- "SMBv1 is enabled on Domain Controllers" - Requires Windows Feature installation with DC restart

### Phase 1: Enable dSHeuristics (Anonymous NSPI Access)
- **IOE:** "Anonymous NSPI access to AD enabled"
- **Method:** Modifies `CN=Directory Service` LDAP object
- **Value:** `00000001` (enables anonymous NSPI)
- **Config:** `InfrastructureSecurity_EnabledSHeuristics=true`
- **Effect:** Immediate (no restart required)

### Phase 2: Enable Print Spooler on Domain Controllers
- **IOE:** "Print spooler service is enabled on a DC"
- **Method:** Sets service startup type to Automatic, starts service
- **Config:** `InfrastructureSecurity_EnablePrintSpooler=true`
- **Effect:** Immediate
- **Security Impact:** Critical - execution vector for privilege escalation

### Phase 3: Disable LDAP Signing via GPO
- **IOE:** "LDAP signing is not required on Domain Controllers"
- **Method:** Creates GPO, sets registry preference, refreshes group policy
- **Registry:** `HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity=0`
- **Config:** `InfrastructureSecurity_DisableLDAPSigning=true`
- **Effect:** After gpupdate refresh (near-immediate)

### Phase 4: Disable SMB Signing via GPO
- **IOE:** "SMB Signing is not required on Domain Controllers"
- **Method:** Creates GPO, sets registry preference, refreshes group policy
- **Registry:** `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature=0`
- **Config:** `InfrastructureSecurity_DisableSMBSigning=true`
- **Effect:** After gpupdate refresh (near-immediate)

### Phase 5: Enable SMBv1 via GPO ⚠️
- **IOE:** "SMBv1 is enabled on Domain Controllers"
- **Method:** Creates GPO, sets registry preference, refreshes group policy
- **Registry:** `HKLM\System\CurrentControlSet\Services\LanmanServer\Parameters\SMB1=1`
- **Config:** `InfrastructureSecurity_EnableSMBv1=true`
- **Effect:** **Requires Domain Controller restart**
- **⚠️ IMPORTANT:** Plan for DC restart if deploying this phase

### Phase 6: Add Anonymous to Pre-Windows 2000 Compatible Access
- **IOE:** "Anonymous access to Active Directory enabled"
- **Method:** Adds well-known SID `S-1-5-7` (ANONYMOUS LOGON) to group
- **Config:** `InfrastructureSecurity_AddAnonymousPre2000=true`
- **Effect:** Immediate

### Phase 7: Disable AdminSDHolder SDProp Protection
- **IOE:** "Operator groups no longer protected by AdminSDHolder and SDProp"
- **Method:** Sets `adminCount=0` on Backup Operators, Account Operators, Print Operators
- **Config:** `InfrastructureSecurity_DisableAdminSDHolder=true`
- **Effect:** Immediate (removes SDProp reapplication)

### Phase 8: Modify Schema Permissions
- **IOE:** "Non-standard schema permissions"
- **Method:** Grants Authenticated Users `GenericWrite` on schema object
- **Config:** `InfrastructureSecurity_ModifySchemaPermissions=true`
- **Effect:** Immediate

### Phase 9: Unsecured DNS Configuration
- **IOE:** "Unsecured DNS configuration"
- **Method:** Sets DNS zones to allow non-secure dynamic updates (`NonsecureAndSecure`)
- **Config:** `InfrastructureSecurity_UnsecuredDNS=true`
- **Effect:** Immediate

## Configuration

Edit `dsp-breakAD.config` to enable/disable individual phases:

```ini
################################################################################
# Module 01: Infrastructure Security
################################################################################

# PHASE 1: Enable dSHeuristics (Anonymous NSPI Access)
InfrastructureSecurity_EnabledSHeuristics=true
InfrastructureSecurity_dSHeuristicsValue=00000001

# PHASE 2: Enable Print Spooler on DCs
InfrastructureSecurity_EnablePrintSpooler=true

# PHASE 3: Disable LDAP Signing on DCs (via GPO)
InfrastructureSecurity_DisableLDAPSigning=true

# PHASE 4: Disable SMB Signing on DCs (via GPO)
InfrastructureSecurity_DisableSMBSigning=true

# PHASE 5: Enable SMBv1 on DCs (via GPO)
# NOTE: Requires Domain Controller restart
InfrastructureSecurity_EnableSMBv1=true

# PHASE 6: Add Anonymous to Pre-Windows 2000 Compatible Access
InfrastructureSecurity_AddAnonymousPre2000=true
```

## Module 00: Preflight

Automatically runs before module selection (unless `-SkipPreflight` is specified).

**Functions:**
1. Validates administrator rights
2. Checks PowerShell version (5.1+)
3. Validates ActiveDirectory module
4. Verifies AD connectivity
5. Lists Domain Controllers
6. Checks replication health
7. Discovers domain information
8. Creates breakAD OUs (for future objects)

## Logging

All execution logged to `logs/dsp-breakAD-YYYYMMDD-HHMMSS.log`

**Log Levels:**
- `[INFO]` - Informational messages
- `[SUCCESS]` - Successfully completed actions
- `[WARNING]` - Non-fatal errors
- `[ERROR]` - Fatal errors

Each log entry includes timestamp, level, and message.

## Important Notes

⚠️ **Lab Use Only** - These modifications deliberately weaken AD security. Run only in non-production lab environments.

⚠️ **Backup First** - Back up your AD before running this tool.

✓ **Reversible** - All changes are logged and documented. Most can be manually reversed (see Reversal Guide below).

⚠️ **SMBv1 Requires Restart** - Phase 5 changes require Domain Controller restart to take effect.

## Reversal Guide

### Remove GPOs Created by Module 01

```powershell
# List GPOs created by dsp-breakAD
Get-GPO -All | Where-Object { $_.DisplayName -like "dsp-breakAD-*" } | Select-Object DisplayName

# Remove specific GPO (e.g., LDAP Signing)
Remove-GPO -Name "dsp-breakAD-LDAP-Signing" -Confirm:$false

# Remove all dsp-breakAD GPOs
Get-GPO -All | Where-Object { $_.DisplayName -like "dsp-breakAD-*" } | Remove-GPO -Confirm:$false
```

### Disable Print Spooler on DCs

```powershell
Get-ADDomainController -Filter * | ForEach-Object {
    Set-Service -Name Spooler -StartupType Disabled -ComputerName $_.HostName
    Stop-Service -Name Spooler -ComputerName $_.HostName -Force
}
```

### Reset dSHeuristics

```powershell
$rootDSE = Get-ADRootDSE
$configNC = $rootDSE.configurationNamingContext
$directoryServicePath = "CN=Directory Service,CN=Windows NT,CN=Services,$configNC"

$ldapPath = "LDAP://$directoryServicePath"
$directoryService = [ADSI]$ldapPath
$directoryService.Put("dSHeuristics", "")
$directoryService.SetInfo()
```

### Remove Anonymous from Pre-Windows 2000 Compatible Access

```powershell
$group = Get-ADGroup "Pre-Windows 2000 Compatible Access"
$groupADSI = [ADSI]"LDAP://$($group.DistinguishedName)"
$groupADSI.Remove("LDAP://<SID=S-1-5-7>")
$groupADSI.SetInfo()
```

## Troubleshooting

### Preflight Fails: "Cannot validate argument on parameter 'SearchBase'"
- Ensure domain can be discovered with `Get-ADDomain`
- Check ActiveDirectory module is loaded
- Verify administrator rights

### Module Fails to Load
- Check module file exists in current directory
- Verify naming convention: `dsp-BreakAD-Module-##-*.psm1`
- Check log file for specific error

### GPO Not Applying
- Run manual `gpupdate /force` on affected DCs
- Check DC event logs for policy errors
- Verify GPO is linked to Domain Controllers OU
- Check DC has read permissions on GPO

### Changes Not Appearing in DSP
- Wait 15-30 minutes for DSP scan to complete
- Force DSP scan if available
- Check logs confirm changes were applied
- Verify changes persisted (don't revert on restart)

## Future Modules

Planned:
- **Module 02:** Account Security
- **Module 03:** AD Delegation
- **Module 04:** Kerberos Security
- **Module 05:** Group Policy Security

## Support & Contact

For issues or questions:
- Check logs in `logs/` folder
- Review PROJECT_NOTES.md for detailed information
- Verify prerequisites are met
- Contact: bob@semperis.com

---

**Version:** 1.0.0  
**Last Updated:** December 2025  
**Status:** Lab/Demo Use Only - Infrastructure Security Module Production Ready