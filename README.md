# dsp-breakAD - AD Security Misconfiguration Simulation Tool

A PowerShell-based utility to deliberately introduce realistic security misconfigurations into a lab Active Directory environment for DSP (Directory Services Protector) demonstration and testing.

**Author:** Bob Lyons (bob@semperis.com)

## Overview

dsp-breakAD allows you to systematically introduce AD security misconfigurations that mirror real-world poorly-configured environments. Each module targets a specific DSP category and can be run independently or in sequence.

## Prerequisites

- PowerShell 5.1 or higher
- Administrator rights on domain-joined machine
- Active Directory PowerShell module
- Connection to at least one Domain Controller
- Lab/test AD forest (NOT production)

## Structure

```
dsp-breakAD/
├── dsp-breakAD.ps1                    # Main orchestration script
├── dsp-breakAD.config                 # Configuration file
├── dsp-BreakAD-Logging.psm1           # Logging module
├── modules/
│   ├── dsp-BreakAD-Module-01-InfrastructureSecurity.psm1
│   ├── dsp-BreakAD-Module-02-AccountSecurity.psm1
│   ├── dsp-BreakAD-Module-03-ADDelegation.psm1
│   ├── dsp-BreakAD-Module-04-KerberosSecurity.psm1
│   └── dsp-BreakAD-Module-05-GroupPolicySecurity.psm1
└── logs/                              # Auto-created, contains execution logs
```

## Quick Start

### Run All Modules
```powershell
.\dsp-breakAD.ps1 -All
```

### Run Specific Module(s)
```powershell
.\dsp-breakAD.ps1 -ModuleNames "InfrastructureSecurity","AccountSecurity"
```

### Interactive Selection
```powershell
.\dsp-breakAD.ps1
```
You'll be prompted to select which modules to run:
- 1) InfrastructureSecurity
- 2) AccountSecurity
- 3) ADDelegation
- 4) KerberosSecurity
- 5) GroupPolicySecurity
- 6) All

## Modules

### Module 1: Infrastructure Security
Targets: AD Infrastructure Security (DSP category)

**Actions:**
- Enables print spooler on all Domain Controllers (Critical: Execution vector)
- Adds users to Schema Admins group (High: Privilege escalation)
- Adds users to Enterprise Admins group (High: Forest-wide privilege)
- Modifies dSHeuristics to enable:
  - Anonymous LDAP access
  - Anonymous NSPI access
  - Weak password operations over non-secure connections

**Config Options:**
- `InfrastructureSecurity_EnablePrintSpooler` - Enable/disable print spooler
- `InfrastructureSecurity_AddToSchemaAdmins` - Number of users to add
- `InfrastructureSecurity_AddToEnterpriseAdmins` - Number of users to add
- `InfrastructureSecurity_ModifydSHeuristics` - Enable/disable dSHeuristics changes

### Module 2: Account Security
Targets: Account Security (DSP category)

**Actions:**
- Creates multiple "break-User-#" accounts with various weak configurations:
  - Password never expires
  - Pre-auth disabled (AS-REP roasting vector)
  - Weak Kerberos encryption (DES, RC4)
  - Unconstrained delegation enabled
  - Constrained delegation to dangerous SPNs
  - Passwords stored in description fields
  - Shared service account scenarios

**Config Options:**
- `AccountSecurity_BadUsersToCreate` - Number of bad users to create
- `AccountSecurity_IncludeNeverExpiringPasswords` - Enable/disable
- `AccountSecurity_IncludePreAuthDisabled` - Enable/disable
- `AccountSecurity_IncludeWeakEncryption` - Enable/disable
- `AccountSecurity_IncludeUnconstrainedDelegation` - Enable/disable
- `AccountSecurity_IncludeConstrainedDelegation` - Enable/disable
- `AccountSecurity_IncludeWeakPasswordStorage` - Enable/disable
- `AccountSecurity_IncludeServiceAccountAbuse` - Enable/disable

### Module 3: AD Delegation
Targets: AD Delegation (DSP category)

**Actions:**
- Grants dangerous permissions to non-admin users
- Creates computers with unconstrained delegation
- Modifies ACLs on sensitive AD objects
- Grants reset password rights to weak users
- Delegation permission abuse scenarios

**Config Options:**
- `ADDelegation_GrantDangerousPermissions` - Enable/disable
- `ADDelegation_IncludeComputerDelegation` - Enable/disable
- `ADDelegation_ModifySensitiveACLs` - Enable/disable
- `ADDelegation_GrantResetPasswordRights` - Enable/disable

### Module 4: Kerberos Security
Targets: Kerberos Security (DSP category)

**Actions:**
- Creates users/computers with DES encryption only
- Creates users with RC4 encryption only
- Creates users with multiple weak encryptions
- Disables pre-auth on computer accounts
- Creates service principals with weak settings

**Config Options:**
- `KerberosSecurity_IncludeDESEncryption` - Enable/disable
- `KerberosSecurity_IncludeRC4Encryption` - Enable/disable
- `KerberosSecurity_IncludeMultipleWeakEncryptions` - Enable/disable
- `KerberosSecurity_DisableComputerPreAuth` - Enable/disable
- `KerberosSecurity_IncludeWeakSPNs` - Enable/disable

### Module 5: Group Policy Security
Targets: Group Policy Security (DSP category)

**Actions:**
- Weakens GPO link permissions at domain level
- Weakens GPO link permissions at DC OU level
- Grants GPO Creator rights to non-admin users
- Attempts to weaken Default Domain Policy
- Disables auditing on sensitive GPOs (limited automation - partial)

**Config Options:**
- `GroupPolicySecurity_WeakenDomainGPOPermissions` - Enable/disable
- `GroupPolicySecurity_WeakenDCOUGPOPermissions` - Enable/disable
- `GroupPolicySecurity_GrantGPOCreatorRights` - Enable/disable
- `GroupPolicySecurity_ModifyDefaultDomainPolicy` - Enable/disable
- `GroupPolicySecurity_DisableGPOAuditing` - Enable/disable

## Configuration

Edit `dsp-breakAD.config` to control module behavior:

```ini
# Enable/disable specific actions
InfrastructureSecurity_EnablePrintSpooler=true
InfrastructureSecurity_AddToSchemaAdmins=2
AccountSecurity_BadUsersToCreate=5
AccountSecurity_IncludeNeverExpiringPasswords=true
# ... etc
```

**General Settings:**
- `DryRun=false` - Log changes without applying them (future feature)
- `TargetDSPScore=60-70` - Informational target score

## Logging

All execution is logged to `logs/dsp-breakAD-YYYYMMDD-HHMMSS.log`

Log levels:
- **INFO** - Informational messages
- **SUCCESS** - Successfully completed actions
- **WARNING** - Non-fatal errors or skipped actions
- **ERROR** - Fatal errors

Each change is also logged with detailed:
- Object affected
- Attribute modified
- Old value → New value
- Timestamp

## Important Notes

⚠️ **Lab Use Only** - These modifications should ONLY be run in a non-production lab environment. They will deliberately weaken AD security.

⚠️ **Backup First** - Back up your AD before running this tool.

⚠️ **Can't Break AD** - This tool is designed NOT to break AD, but to weaken it realistically. However:
- Do not run on production
- Test in isolated lab first
- Monitor DC health after running

✓ **Reversibility** - All changes are documented in logs. Most can be manually reversed by:
- Removing created users (break-*)
- Re-securing privilege groups
- Resetting dSHeuristics
- Reapplying proper group policies

## Common Tasks

### Revert Changes Manually

1. **Remove created users:**
   ```powershell
   Get-ADUser -Filter "Name -like 'break-*'" | Remove-ADUser -Confirm:$false
   ```

2. **Remove users from Schema Admins:**
   ```powershell
   $group = Get-ADGroup "Schema Admins"
   Get-ADUser -Filter "Name -like 'break-*'" | Remove-ADGroupMember -Identity $group -Confirm:$false
   ```

3. **Reset dSHeuristics:**
   ```powershell
   $dirService = Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,DC=corp,DC=local"
   Set-ADObject -Identity $dirService -Replace @{dSHeuristics = ""} 
   ```

### Check Current Score in DSP

1. Log into your DSP instance
2. Navigate to Security > Overview
3. Review IOE AD categories to see impact of modules

### Run Modules Incrementally

Run one module at a time, check DSP score after each, then add more:

```powershell
.\dsp-breakAD.ps1 -ModuleNames "InfrastructureSecurity"
# Check DSP score, observe findings
.\dsp-breakAD.ps1 -ModuleNames "AccountSecurity"
# Check DSP score again
# Continue...
```

## Troubleshooting

### Script fails with "Administrator privileges required"
- Run PowerShell as Administrator
- Verify your account has Domain Admin rights

### Modules don't execute
- Check that module files exist in `modules/` folder
- Verify naming convention: `dsp-BreakAD-Module-##-*.psm1`
- Check logs for specific errors

### Changes not appearing in DSP
- Wait for DSP assessment to complete (usually 15-30 min)
- Force DSP scan if available
- Verify changes were logged successfully

### Can't undo changes
- Reference the log file for exact changes made
- Manually revert using documented LDAP paths
- Restore from backup if available

## Support

For questions or issues:
- Check log files in `logs/` folder
- Review module-specific comments in code
- Contact: bob@semperis.com

---

**Version:** 1.0.0  
**Last Updated:** December 2025  
**Status:** Lab/Demo Use Only