## DSP Break AD - Lower Your DSP Score Intentionally

Tool to programmatically introduce Active Directory security misconfigurations targeting Directory Services Protector (DSP) Indicators of Exposure (IOEs).

**Purpose**: Demonstrate DSP detection and reporting capabilities in lab environments by systematically introducing known security gaps.

**⚠️ WARNING**: Lab use only. Do not run in production. These changes deliberately weaken AD security.

---

## Quick Start

```powershell
# Run all modules interactively
.\dsp-breakAD.ps1

# Run specific modules
.\dsp-breakAD.ps1 -ModuleNames "AccountSecurity", "InfrastructureSecurity"

# Run all modules non-interactively
.\dsp-breakAD.ps1 -All
```

---

## Project Structure

```
dsp-breakAD/
├── dsp-breakAD.ps1                           # Main orchestration script
├── dsp-breakAD.config                        # Configuration (enable/disable IOEs)
├── dsp-BreakAD-Logging.psm1                  # Logging module
├── modules/
│   ├── dsp-BreakAD-Module-00-Preflight.psm1  # Environment setup & validation
│   ├── dsp-BreakAD-Module-01-InfrastructureSecurity.psm1
│   ├── dsp-BreakAD-Module-02-AccountSecurity.psm1
│   ├── dsp-BreakAD-Module-03-ADDelegation.psm1
│   ├── dsp-BreakAD-Module-04-KerberosSecurity.psm1
│   └── dsp-BreakAD-Module-05-GroupPolicySecurity.psm1
└── logs/
    └── dsp-breakAD-YYYYMMDD-HHMMSS.log      # Execution logs
```

---

## Execution Flow

1. **Load Configuration** - Read `dsp-breakAD.config`
2. **Run Preflight** - Validate environment, create OUs, discover domain/DC info
3. **Module Selection** - User selects which modules to run (or specify via parameter)
4. **Load Modules** - Import selected PowerShell modules
5. **Execute Modules** - Run each module sequentially with domain context
6. **Log Results** - Write detailed execution log to `logs/` directory

---

## Module: Preflight (Module 00)

**Purpose**: Environment validation and setup

**Functions**:
- Validate administrator rights
- Check PowerShell version (5.1+ required)
- Validate ActiveDirectory module availability
- Verify AD domain connectivity
- Discover domain and DC information
- Create BreakAD OU structure for test objects

**Output**: Environment hashtable passed to all modules

**Can be skipped**: `.\dsp-breakAD.ps1 -SkipPreflight` (not recommended)

---

## Module: Infrastructure Security (Module 01)

**Target Category**: AD Infrastructure Security IOEs

**IOEs Implemented**: 8 of 9

**Skipped IOE**: SMBv1 enablement (requires Windows Feature installation + DC restart)

### Phase 1: Enable dSHeuristics (Anonymous NSPI Access)
- **IOE**: Anonymous NSPI access to AD enabled
- **Method**: Modifies `CN=Directory Service` LDAP object
- **Config**: `InfrastructureSecurity_EnabledSHeuristics=true`

### Phase 2: Enable Print Spooler on DCs
- **IOE**: Print spooler service enabled on DC
- **Method**: Sets service startup to Automatic, starts service
- **Config**: `InfrastructureSecurity_EnablePrintSpooler=true`
- **Impact**: Critical - PrintNightmare execution vector

### Phase 3: Disable LDAP Signing via GPO
- **IOE**: LDAP signing not required on DCs
- **Method**: Creates GPO, sets registry preference
- **Config**: `InfrastructureSecurity_DisableLDAPSigning=true`

### Phase 4: Disable SMB Signing via GPO
- **IOE**: SMB signing not required
- **Method**: Creates GPO, sets registry preference
- **Config**: `InfrastructureSecurity_DisableSMBSigning=true`

### Phase 5: Enable SMBv1 on DCs
- **IOE**: SMBv1 enabled on Domain Controllers
- **Status**: SKIPPED - requires Windows Feature + restart
- **Config**: `InfrastructureSecurity_EnableSMBv1=false`

### Phase 6: Add Anonymous to Pre-Windows 2000 Compatible Access
- **IOE**: Pre-Windows 2000 Compatible Access group membership
- **Method**: Adds Anonymous to group
- **Config**: `InfrastructureSecurity_AddAnonymousPre2000=true`

### Phase 7: Modify Schema Permissions
- **IOE**: Unauthorized schema modifications possible
- **Method**: Grants Authenticated Users GenericWrite on schema
- **Config**: `InfrastructureSecurity_ModifySchemaPermissions=true`

### Phase 8: Disable LDAP Channel Binding
- **IOE**: LDAP channel binding not enforced
- **Method**: Registry modification via GPO
- **Config**: `InfrastructureSecurity_DisableLDAPChannelBinding=true`

### Phase 9: Unsecured DNS Configuration
- **IOE**: DNS allows unsecured dynamic updates
- **Method**: Sets DNS zones to NonsecureAndSecure
- **Config**: `InfrastructureSecurity_UnsecuredDNS=false` (disabled by default)

---

## Module: Account Security (Module 02)

**Target Category**: Account Security IOEs

**IOEs Implemented**: 10 of 13

**Account Naming**: All test accounts use `break-` prefix with short suffixes to stay under 20-character SAM limit

### IOE 1: Built-in Administrator Recently Used
- **Status**: SKIPPED
- **Reason**: Cannot reset built-in Administrator password in lab
- **Config**: Disabled (commented in module)

### IOE 3: Privileged Accounts with Password Never Expires
- **Config**: `AccountSecurity_PrivilegedPwdNeverExpires=true`
- **Action**: Creates accounts, adds to Domain Admins, enables PasswordNeverExpires flag
- **Accounts**: `break-ppwd###` (3 accounts)

### IOE 4: User Accounts with Reversible Encryption
- **Config**: `AccountSecurity_ReversibleEncryption=true`
- **Action**: Creates accounts with userAccountControl flag 0x80 (ENCRYPTED_TEXT_PASSWORD_ALLOWED)
- **Accounts**: `break-renc###` (2 accounts)

### IOE 5: User Accounts with DES Encryption
- **Config**: `AccountSecurity_DESEncryption=true`
- **Action**: Creates accounts with msDS-SupportedEncryptionTypes=1 (DES only)
- **Accounts**: `break-des###` (2 accounts)

### IOE 6: User Accounts with Password Not Required
- **Config**: `AccountSecurity_PwdNotRequired=true`
- **Action**: Creates accounts with PasswordNotRequired flag enabled
- **Accounts**: `break-npwd###` (2 accounts)

### IOE 7: Users with Kerberos Pre-authentication Disabled
- **Config**: `AccountSecurity_PreAuthDisabled=true`
- **Action**: Creates accounts with userAccountControl flag 0x400000 (DONT_REQUIRE_PREAUTH)
- **Accounts**: `break-prea###` (2 accounts)

### IOE 8: Unprivileged Accounts with adminCount=1
- **Config**: `AccountSecurity_UnprivilegedAdminCount=true`
- **Action**: Creates regular users with adminCount=1 attribute
- **Accounts**: `break-acnt###` (2 accounts)

### IOE 9: Accounts with Old Passwords (90+ days)
- **Status**: SKIPPED
- **Reason**: pwdLastSet cannot be reliably set post-creation via ADSI
- **Config**: Disabled (commented in module)

### IOE 10: Privileged Users that are Disabled
- **Config**: `AccountSecurity_DisabledPrivilegedUsers=true`
- **Action**: Creates accounts, adds to Domain Admins, then disables them
- **Accounts**: `break-dpriv###` (2 accounts)

### IOE 11: Recent Privileged Account Creation
- **Config**: `AccountSecurity_RecentPrivilegedCreation=true`
- **Action**: Creates accounts and adds to Domain Admins + Schema Admins
- **Accounts**: `break-npr###` (2 accounts)

### IOE 12: Recent AD Object Creation (within 10 days)
- **Config**: `AccountSecurity_RecentObjectCreation=true`
- **Action**: Creates regular user accounts
- **Accounts**: `break-nobj###` (3 accounts)

### IOE 13: Smart Card with Old Password
- **Status**: SKIPPED
- **Reason**: pwdLastSet cannot be reliably set post-creation via ADSI
- **Config**: Disabled (commented in module)

### Account Naming
- **Format**: `break-{suffix}###` where ### is random 100-999
- **Example**: `break-ppwd547`, `break-acnt823`
- **Reason**: Random suffix avoids AD Recycle Bin conflicts on repeated runs

### Passwords
- **Generation**: Random 32-character strings (matching Module 1 approach)
- **Characters**: ASCII 33-126 (all printable non-whitespace characters)
- **Complexity**: Always meets Windows default complexity requirements
- **Idempotent**: Module generates new passwords on each run (accounts deleted and recreated)

---

## Module: AD Delegation (Module 03)

**Target Category**: AD Delegation IOEs

**Status**: Framework in place, not fully implemented

**Planned IOEs**:
- AdminSDHolder inheritance enabled
- Unprivileged users added to Account Operators
- Unprivileged users added to Backup Operators
- Unprivileged users added to Server Operators
- Unprivileged users added to Print Operators
- Reset password rights granted to non-admins
- User creation rights granted to non-admins
- DNS Admin rights granted to non-admins

---

## Module: Kerberos Security (Module 04)

**Target Category**: Kerberos Security IOEs

**Status**: Framework in place, not fully implemented

---

## Module: Group Policy Security (Module 05)

**Target Category**: Group Policy Security IOEs

**Status**: Framework in place, not fully implemented

---

## Configuration (dsp-breakAD.config)

Edit this file to enable/disable individual IOEs:

```ini
# Module 01: Infrastructure Security
InfrastructureSecurity_EnabledSHeuristics=true
InfrastructureSecurity_EnablePrintSpooler=true
InfrastructureSecurity_DisableLDAPSigning=true
InfrastructureSecurity_DisableSMBSigning=true
InfrastructureSecurity_EnableSMBv1=false
InfrastructureSecurity_AddAnonymousPre2000=true
InfrastructureSecurity_ModifySchemaPermissions=true
InfrastructureSecurity_DisableLDAPChannelBinding=true
InfrastructureSecurity_UnsecuredDNS=false

# Module 02: Account Security
AccountSecurity_UseBuiltInAdmin=true
AccountSecurity_PrivilegedPwdNeverExpires=true
AccountSecurity_ReversibleEncryption=true
AccountSecurity_DESEncryption=true
AccountSecurity_PwdNotRequired=true
AccountSecurity_PreAuthDisabled=true
AccountSecurity_UnprivilegedAdminCount=true
AccountSecurity_OldPasswords=false
AccountSecurity_DisabledPrivilegedUsers=true
AccountSecurity_RecentPrivilegedCreation=true
AccountSecurity_RecentObjectCreation=true
AccountSecurity_SmartCardOldPassword=false
```

---

## Logging

All execution logged to `logs/dsp-breakAD-YYYYMMDD-HHMMSS.log`

**Log Levels**:
- `[INFO]` - Informational messages
- `[SUCCESS]` - Successfully completed actions
- `[WARNING]` - Non-fatal errors
- `[ERROR]` - Fatal errors

**Each entry includes**: Timestamp, level, and message

---

## Idempotency

**Module 02 (Account Security) is fully idempotent**:
- Safe to run multiple times
- Deletes and recreates all `break-*` accounts on each run
- Uses random account name suffixes to avoid recycle bin conflicts
- Generates new random passwords each run

**Other modules**: Generally idempotent (checks for existing state before modifying)

---

## Test Accounts Created

All test accounts are prefixed with `break-` and use random numeric suffixes (100-999).

**Account Cleanup**:
```powershell
# Remove all break-* accounts
Get-ADUser -Filter {SamAccountName -like "break-*"} | Remove-ADUser -Confirm:$false

# Remove test OU (if empty)
Remove-ADOrganizationalUnit -Identity "OU=BreakAD,DC=..." -Confirm:$false
```

---

## Troubleshooting

### "Administrator privileges required"
- Run PowerShell as Administrator
- Account must be Domain Admin

### "ActiveDirectory module not found"
- Install RSAT (Remote Server Administration Tools)
- Or run on a Domain Controller with AD tools installed

### "The parameter is incorrect" (pwdLastSet errors)
- These IOEs are skipped by design (Module 02, IOEs 9 and 13)
- Cannot reliably set pwdLastSet post-creation via PowerShell

### "The password does not meet requirements"
- Domain password policy is very strict
- Module uses 32-character random passwords (should work)
- Check: `Get-ADDefaultDomainPasswordPolicy`

### Account creation fails with "name already in use"
- Old accounts still in AD Recycle Bin
- Wait 180 days (default tombstone) or wait for script to regenerate with new random suffix
- Or manually purge: Requires LDAP manipulation (advanced)

---

## Parameters

```powershell
# Run specific modules
.\dsp-breakAD.ps1 -ModuleNames "AccountSecurity"
.\dsp-breakAD.ps1 -ModuleNames "InfrastructureSecurity", "AccountSecurity"

# Run all modules
.\dsp-breakAD.ps1 -All

# Skip preflight (not recommended)
.\dsp-breakAD.ps1 -SkipPreflight

# Interactive (default)
.\dsp-breakAD.ps1
```

---

## Safety Notes

- ✓ Changes are logged and documented
- ✓ Most changes can be manually reversed
- ⚠️ Run only in lab environments
- ⚠️ Backup AD before running
- ⚠️ Some changes (like Print Spooler) introduce real security risks
- ⚠️ GPO changes affect all Domain Controllers

---

## Author

Bob Lyons (bob@semperis.com)  
Semperis Sales Architect

---

## Version History

- **1.0.0** - Initial release with Modules 01-02 fully implemented
  - Module 01: Infrastructure Security (8/9 IOEs)
  - Module 02: Account Security (11/13 IOEs)
  - Module 00: Preflight validation