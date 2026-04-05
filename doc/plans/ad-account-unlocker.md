# Plan: AD Account Unlocker — Impacket-Style CLI Tool

## Summary

Build a Python script (`unlockAccount.py`) that unlocks locked-out Active Directory accounts via LDAP. It accepts a single username or a file of usernames, authenticates to a domain controller using the same credential/connection arguments as impacket example tools (e.g., `smbclient.py`), and resets the `lockoutTime` attribute to `0` for each target account.

## Problem

There is no standalone impacket-style CLI tool for unlocking AD accounts. Existing options require GUI tools (ADUC), PowerShell on a domain-joined machine, or manual LDAP operations. Pentesters and sysadmins need a portable, cross-platform tool that fits the impacket workflow they already know.

## Goal

After implementation, a user can run:

```
python3 unlockAccount.py domain/admin:Password123@dc01.corp.local -user jsmith
python3 unlockAccount.py domain/admin:Password123@dc01.corp.local -user-file locked_users.txt
```

And have the specified accounts unlocked (lockoutTime reset to 0), with clear per-user success/failure output.

## Design

### CLI Interface

Mirror the `smbclient.py` / `GetADUsers.py` argument pattern exactly:

- **Positional `target`**: `[[domain/]username[:password]@]<targetName or address>` — parsed with `impacket.examples.utils.parse_target`
- **`-user`**: Single sAMAccountName to unlock
- **`-user-file`**: Path to a file containing one sAMAccountName per line
- At least one of `-user` or `-user-file` is required
- **Authentication group**: `-hashes`, `-no-pass`, `-k`, `-aesKey` (identical to impacket tools)
- **Connection group**: `-dc-ip`, `-dc-host` (identical to GetADUsers.py)
- **`-ts`**: Timestamp logging output
- **`-debug`**: DEBUG log level

### LDAP Connection

Use impacket's native `impacket.ldap.ldap.LDAPConnection`:

1. Determine target: prefer `-dc-host`, fall back to `-dc-ip`, fall back to the address from `parse_target`
2. Connect via `ldap://target` with NTLM auth (`login()`)
3. If `strongerAuthRequired` error, retry via `ldaps://target`
4. For Kerberos (`-k`), use `kerberosLogin()` instead
5. Derive `baseDN` from the domain (split on `.`, join as `DC=x,DC=y`)

This is the exact pattern from `GetADUsers.py` lines 136-173.

### Unlock Logic

For each target username:

1. **Search** for the user via LDAP filter `(sAMAccountName=<username>)`, requesting attributes `lockoutTime` and `userAccountControl`
2. **Check** if the account is actually locked (`lockoutTime > 0` means locked)
3. **Unlock** by sending an LDAP ModifyRequest setting `lockoutTime` to `0`
   - Build the modify request using impacket's ASN1 types: `ModifyRequest` with `Operation('replace')` on `PartialAttribute('lockoutTime', ['0'])`
   - Send via `LDAPConnection.sendReceive()` and check the `ModifyResponse` result code
4. **Report** per-user: success, already-unlocked, user-not-found, or permission-denied

### Why `lockoutTime = 0` (not `userAccountControl`)?

The `UF_LOCKOUT` bit (0x10) in `userAccountControl` is a **computed/read-only** attribute in Active Directory. Setting it directly does not reliably unlock accounts. The correct and documented way to unlock an AD account is to reset `lockoutTime` to `0`. This is what ADUC, PowerShell's `Unlock-ADAccount`, and SAMR-based tools all do under the hood.

### Output Format

Use impacket's logger (`impacket.examples.logger`) for consistent output styling:

```
Impacket v0.11.0 - Copyright ...

[*] Connecting to dc01.corp.local via LDAP
[*] Using NTLM authentication
[*] BaseDN: DC=corp,DC=local
[*] Processing user: jsmith
[*]   lockoutTime: 133580000000000000 (locked)
[*]   Successfully unlocked jsmith
[*] Processing user: admin
[*]   lockoutTime: 0 (not locked)
[*]   Account admin is not locked — skipping
[*] Done. 1 account(s) unlocked, 1 already unlocked, 0 errors.
```

## Affected Components

- `unlockAccount.py` (new): Main script — CLI parsing, LDAP connect, search, modify, output. ~200 lines.

No other files are modified. The script is self-contained, depending only on `impacket` and `ldap3` (both already installed).

## Dependencies

All already installed on this system:

- `impacket 0.11.0` — target parsing, LDAP connection, logger, ASN1 types
- `ldap3 2.9.1` — only if impacket's native LDAP modify proves problematic (fallback)
- Python 3 standard library — `argparse`, `logging`, `sys`, `getpass`
