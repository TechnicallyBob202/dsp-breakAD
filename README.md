# DSP Break AD - Lower Your DSP Score Intentionally

Tool to programmatically introduce Active Directory security misconfigurations targeting Directory Services Protector (DSP) Indicators of Exposure (IOEs).

**Purpose**: Demonstrate DSP detection and reporting capabilities in lab environments by systematically introducing known security gaps.

**⚠️ WARNING**: Lab use only. Do not run in production. These changes deliberately weaken AD security.

---

## Quick Start

```powershell
# Run interactively (select modules)
.\dsp-breakAD.ps1

# Run all modules
.\dsp-breakAD.ps1 -All

# Run specific modules
.\dsp-breakAD.ps1 -ModuleNames "GroupPolicySecurity", "AccountSecurity"
```

---

## Project Structure

```
dsp-breakAD/
├── dsp-breakAD.ps1                              # Main orchestration script
├── dsp-breakAD.config                           # Configuration (OU paths only)
├── dsp-BreakAD-Logging.psm1                     # Logging module
├── modules/
│   ├── dsp-BreakAD-Module-00-Preflight.psm1     # Environment setup & validation
│   ├── dsp-BreakAD-Module-01-GroupPolicySecurity.psm1
│   ├── dsp-BreakAD-Module-02-AccountSecurity.psm1
│   ├── dsp-BreakAD-Module-03-ADDelegation.psm1
│   └── dsp-BreakAD-Module-04-KerberosSecurity.psm1
└── logs/
    └── dsp-breakAD-YYYYMMDD-HHMMSS.log         # Execution logs
```

---

## Execution Flow

1. **Run Preflight** - Validates environment, creates OU structure, discovers domain/DC
2. **Auto-discover Modules** - Scans `modules/` directory for all `dsp-BreakAD-Module-*.psm1` files (except Preflight)
3. **Module Selection** - User selects which modules to run interactively (or specify via `-ModuleNames` / `-All`)
4. **Load & Execute** - Load selected modules and execute sequentially with domain context
5. **Log Results** - Write detailed execution log to `logs/` directory

---

## Module: Preflight (Module 00)

**Purpose**: Environment validation and setup

**Functions**:
- Validate administrator rights
- Check PowerShell version (5.1+ required)
- Validate ActiveDirectory module availability
- Verify AD domain connectivity
- Discover domain and DC information
- Create BreakAD OU structure:
  - `OU=BreakAD,DC=...`
  - `OU=Users,OU=BreakAD,DC=...`
  - `OU=Computers,OU=BreakAD,DC=...`

**Output**: Environment hashtable (Domain, DomainController, Config) passed to all modules

**Auto-run**: Always runs first, cannot be skipped

---

## Module: Group Policy Security (Module 01)

**Target Category**: Group Policy Security IOEs

**IOEs Implemented**: 10 of 13

### Phase 1-2: Modify Default Domain/Controllers Policies
- **IOEs**: Changes to Default Domain/Controllers Policy
- **Method**: Sets innocuous registry value (SubmitControl=1) in LSA key
- **Impact**: Minimal, non-destructive

### Phase 3: Create Test GPOs
- **Action**: Creates 3 test GPOs (`breakAD-LinkTest-Domain/Site/OU`)
- **Location**: BreakAD OU

### Phase 4: Link/Unlink Operations
- **IOEs**: Changes to GPO linking at domain/site level
- **Method**: New-GPLink and link/unlink operations on test GPOs
- **Impact**: Creates change history for DSP detection

### Phase 5: Dangerous User Rights
- **IOE**: Dangerous user rights granted by GPO
- **Method**: Creates GptTmpl.inf in SYSVOL with SeServiceLogonRight, SeDebugPrivilege, SeTakeOwnershipPrivilege
- **Target**: Test user (break-dangrights-###)

### Phase 6: Logon Script Path
- **IOE**: Dangerous GPO logon script path
- **Method**: Creates script file in SYSVOL with Everyone:Modify ACL + Scripts.ini registration
- **Location**: Test GPO User\Scripts\Logon directory

### Phase 7: Weak LM Hash Storage
- **IOE**: GPO weak LM hash storage enabled
- **Method**: Adds Registry Values section to GptTmpl.inf with NoLMHash=0
- **Location**: Test GPO GptTmpl.inf

### Phase 8: GPO Linking Delegation
- **IOEs**: GPO linking delegation at domain/site/DC OU levels
- **Method**: Grants LinkGPO and gPLink write permissions via ACLs
- **Targets**: 
  - BreakAD OU (domain-level delegation)
  - First available site (site-level)
  - Domain Controllers OU (DC OU-level)
- **User**: break-gpo-delegate-###

### Phase 9: Force Group Policy Update
- **Action**: Runs `gpupdate /force` to apply changes

**IOEs NOT Firing**:
- Reversible passwords (Groups.xml created but DSP not detecting)
- Writable shortcuts (removed - DSP not detecting)

---

## Module: Account Security (Module 02)

**Target Category**: Account Security IOEs

**IOEs Implemented**: 18 of 35+

### Phase 1: Create Test Accounts with Dangerous Attributes

**IOE 1: Unprivileged accounts with adminCount=1**
- Account: `break-admincnt-###`
- Attribute: adminCount=1

**IOE 2: User accounts with reversible encryption**
- Account: `break-revenc-###`
- Attribute: AllowReversiblePasswordEncryption=true

**IOE 3: User accounts with DES encryption**
- Account: `break-des-###`
- Attribute: msDS-SupportedEncryptionTypes=1

**IOE 4: User accounts with password not required**
- Account: `break-nopwd-###`
- Attribute: PasswordNotRequired=true

**IOE 5: Users with Kerberos pre-authentication disabled**
- Account: `break-nopreauth-###`
- Attribute: userAccountControl=0x1000010 (DONT_REQUIRE_PREAUTH)

**IOE 11: Users with Password Never Expires flag set**
- Account: `break-neverexp-###`
- Attribute: PasswordNeverExpires=true

**IOE 10: Users with old passwords**
- Account: `break-oldpwd-###`
- Method: Sets pwdLastSet=-1 (forces AD recomputation)

### Phase 2: Create Privileged Test Account
- Account: `break-admin-###`
- Added to Domain Admins
- **IOE 7**: Privileged accounts with password never expires (PasswordNeverExpires=true)

### Phase 3: Group Membership Changes

**IOE 12**: Changes to privileged group membership
- Adds test accounts to:
  - Schema Admins
  - Domain Admins
  - DnsAdmins

**IOE 13**: Computer accounts in privileged groups
- Creates test computer: `break-comp-###`
- Adds to Domain Admins

**IOE 16**: Admins with Kerberos pre-authentication disabled
- Adds break-nopreauth account to Domain Admins

**IOE 14**: Schema Admins group is not empty
- Adds break-revenc account to Schema Admins

**IOE 9**: Unprivileged principals as DNS Admins
- Adds break-nopwd account to DnsAdmins

**IOE 18**: Distributed COM Users group not empty
- Adds test account to Distributed COM Users

**IOE 19**: Performance Log Users group not empty
- Adds test account to Performance Log Users

### Phase 4: Fine-Grained Password Policy (PSO)

**IOE 8**: Privileged users with weak password policy
- Creates PSO: `break-weakpso-###`
- Settings:
  - MinPasswordLength: 4
  - PasswordHistoryCount: 1
  - MaxPasswordAge: 365 days
- Applied to: break-admin-### (privileged account)

### Account Naming
- **Format**: `break-{purpose}-###` where ### is random 100-999
- **Example**: `break-revenc547`, `break-admin823`
- **Reason**: Random suffix avoids AD Recycle Bin conflicts on repeated runs

---

## Module: AD Delegation (Module 03)

**Target Category**: AD Delegation IOEs

**IOEs Implemented**: 7 safe + 6 caution (documented but not implemented)

### Phase 1: Create Test Accounts and Groups
- Test user: `break-deleg-###`
- Test privileged group: `break-privileged-###`

### Phase 2: Built-in Guest Account Enabled
- **IOE 1**: Enables built-in Guest account

### Phase 3: gMSA Access Control
- **IOE 4**: Non-privileged users with access to gMSA passwords
- Creates gMSA and grants test user read access to msDS-GroupMSAMembership

### Phase 4: Computer Account Creation Rights
- **IOE 5**: Unprivileged users can add computer accounts to domain
- Grants CreateChild permission on Computer class to test user on BreakAD OU

### Phase 5: Server Trust Account Permissions
- **IOE 6**: Users with permissions to set Server Trust Account
- Creates test computer and grants Reset-Password extended right to test user

### Phase 6: Unprivileged Owner on Privileged Group
- **IOE 7**: Privileged objects with unprivileged owners
- Sets test user as owner of test privileged group

### Phase 7: Group Membership without adminCount
- **IOE 8**: Objects in privileged groups without adminCount=1
- Adds test user to privileged group without setting adminCount

### Phase 8: DC Sync Rights (CAUTION)
- **IOE 12**: Non-default principals with DC Sync rights
- ⚠️ **WARNING**: Grants sensitive replication rights to test user
- Must be removed after testing - do not leave active

**Documented but not implemented (CAUTION/HIGH RISK)**:
- Permission changes on AdminSDHolder
- Inheritance enabled on AdminSDHolder
- Domain Controller owner is not administrator
- Delegation changes to Domain NC head
- Non-default access to DPAPI key
- Computer RBCD, krbtgt RBCD, and other high-risk IOEs

---

## Module: Kerberos Security (Module 04)

**Target Category**: Kerberos Security IOEs

**IOEs Implemented**: 7 of 10 safe IOEs firing

### Phase 1: Create Test Accounts and Computers
- 5 test users: `break-kerb-user1-###` through `break-kerb-user5-###`
- 3 test computers: `break-kerb-c1-###`, `break-kerb-c2-###`, `break-kerb-c3-###`

### Phase 2: altSecurityIdentities
- **IOE 1**: Accounts with altSecurityIdentities configured
- Sets `altSecurityIdentities="Kerberos=altuser@REALM"` on test user

### Phase 3: SPN Configuration
- **IOE 2**: Privileged users with SPN defined
  - Adds SPN to test user
  - Adds user to Domain Admins
- **IOE 3**: Users with SPN defined
  - Adds SPN to regular test user

### Phase 4: RC4-Only Encryption
- **IOE 4**: Primary users with SPN not supporting AES encryption
- Sets `msDS-SupportedEncryptionTypes=4` (RC4 only, no AES)

### Phase 5: userPassword Attribute
- **IOE 6**: Users with userPassword attribute set
- Sets cleartext password in userPassword attribute (legacy/risky)

### Phase 6: Protocol Transition Delegation
- **IOE 7**: Kerberos protocol transition delegation configured
- Sets `msDS-AllowedToDelegateTo` with protocol transition flag

### Phase 7: Constrained Delegation
- **IOE 8**: Objects with constrained delegation configured
- Sets `msDS-AllowedToDelegateTo` on test computer

**IOEs NOT Firing** (not implemented):
- Ghost SPN delegation (no detection)
- Unconstrained delegation (no detection)
- Protocol transition to DC (not tested)

**Documented but not implemented** (CAUTION/HIGH RISK):
- RBCD on computers/DCs/krbtgt
- CVE exploit patterns
- krbtgt with old password
- Other high-risk Kerberos IOEs

---

## Configuration (dsp-breakAD.config)

Currently minimal - only OU paths:

```ini
################################################################################
# OU Configuration
################################################################################
BreakAD_RootOU=BreakAD
BreakAD_UsersOU=Users
BreakAD_ComputersOU=Computers
```

**Note**: Individual IOEs are not configurable via config file. Edit modules directly to enable/disable specific IOEs.

---

## Logging

All execution logged to `logs/dsp-breakAD-YYYYMMDD-HHMMSS.log`

**Log Levels**:
- `[INFO]` - Informational messages
- `[SUCCESS]` - Successfully completed actions
- `[WARNING]` - Non-fatal errors (IOE not applicable)
- `[ERROR]` - Fatal errors (stops execution)

**Each entry includes**: Timestamp, level, and message

---

## Idempotency

**All modules are fully idempotent**:
- Safe to run multiple times
- Test accounts deleted and recreated on each run
- Uses random numeric suffixes (100-999) to avoid recycle bin conflicts
- Generates new random passwords each run
- GPO operations are overwrite-safe
- ACL operations use Add (idempotent)

---

## Test Account Cleanup

All test accounts are prefixed with `break-` and use random numeric suffixes (100-999).

```powershell
# Remove all break-* users
Get-ADUser -Filter {SamAccountName -like "break-*"} -SearchBase "OU=BreakAD,DC=..." | Remove-ADUser -Confirm:$false

# Remove all break-* computers
Get-ADComputer -Filter {Name -like "break-*"} -SearchBase "OU=BreakAD,DC=..." | Remove-ADComputer -Confirm:$false

# Remove all break-* groups
Get-ADGroup -Filter {Name -like "break-*"} -SearchBase "OU=BreakAD,DC=..." | Remove-ADGroup -Confirm:$false

# Remove test GPOs
Get-GPO -Name "breakAD-*" | Remove-GPO -Confirm:$false

# Remove BreakAD OU (if empty)
Remove-ADOrganizationalUnit -Identity "OU=BreakAD,DC=..." -Confirm:$false
```

---

## Parameters

```powershell
# Interactive module selection (default)
.\dsp-breakAD.ps1

# Run all modules
.\dsp-breakAD.ps1 -All

# Run specific modules
.\dsp-breakAD.ps1 -ModuleNames "GroupPolicySecurity"
.\dsp-breakAD.ps1 -ModuleNames "GroupPolicySecurity", "AccountSecurity"
```

---

## Safety Notes

- ✓ All changes are logged and documented
- ✓ Most changes can be manually reversed
- ✓ All test accounts scoped to BreakAD OU
- ✓ Preflight validates environment before making changes
- ⚠️ Run only in lab environments
- ⚠️ Backup AD before running
- ⚠️ Some modules introduce real security risks (e.g., Kerberos pre-auth disabled)
- ⚠️ GPO changes affect all Domain Controllers

---

## Troubleshooting

### "Administrator privileges required"
- Run PowerShell as Administrator
- Account must be Domain Admin

### "ActiveDirectory module not found"
- Install RSAT (Remote Server Administration Tools)
- Or run on a Domain Controller with AD tools installed

### "The name provided is not a properly formed account name"
- Computer names exceed 15-character sAMAccountName limit
- Module auto-generates shorter names
- If error persists, check DC logs for naming conflicts

### "Cannot convert 'System.Object[]' to Hashtable" (SPN errors)
- Use `-ServicePrincipalNames @{Add="..."}` syntax, not `@("...")`
- Module has been corrected

### Account creation fails with "name already in use"
- Old accounts still in AD Recycle Bin
- Wait for new random suffix on next run
- Or manually purge via LDAP (advanced)

---

## IOE Coverage Summary

| Category | Module | IOEs Implemented | Status |
|----------|--------|------------------|--------|
| Group Policy Security | 01 | 10/13 | Partial |
| Account Security | 02 | 18/35+ | Partial |
| AD Delegation | 03 | 7/21 | Partial |
| Kerberos Security | 04 | 7/21 | Partial |
| **TOTAL** | **4 modules** | **42/90+** | **Expanding** |

---

## Author

Bob Lyons (bob@semperis.com)  
Semperis Sales Architect

---

## Version History

- **1.0.0** - Initial release with 4 modules
  - Module 01: Group Policy Security (10/13 IOEs)
  - Module 02: Account Security (18/35+ IOEs)
  - Module 03: AD Delegation (7/21 IOEs, 6 documented but not implemented)
  - Module 04: Kerberos Security (7/21 IOEs)
  - Module 00: Preflight validation