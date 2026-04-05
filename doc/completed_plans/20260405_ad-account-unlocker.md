<!-- Review 1 completed: 2026-04-05 -->
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

Use the `smbclient.py` positional target format with `GetADUsers.py`-style connection overrides:

- **Positional `target`**: `[[domain/]username[:password]@]<targetName or address>` — parsed with `impacket.examples.utils.parse_target`, which returns `(domain, username, password, remote_name)`
- **`-user`**: Single sAMAccountName to unlock
- **`-user-file`**: Path to a file containing one sAMAccountName per line
- At least one of `-user` or `-user-file` is required
- **Authentication group**: `-hashes`, `-no-pass`, `-k`, `-aesKey` (identical to impacket tools)
- **Connection group**: `-dc-ip`, `-dc-host` — these override the `remote_name` parsed from the positional target
- **`-ts`**: Timestamp logging output
- **`-debug`**: DEBUG log level

Note: `GetADUsers.py` uses `parse_credentials` (no `@host` in positional arg). This tool uses `parse_target` (smbclient-style) so the DC address can be specified inline. `-dc-host` and `-dc-ip` take precedence when provided.

### LDAP Connection

Use impacket's native `impacket.ldap.ldap.LDAPConnection`:

1. Determine target: prefer `-dc-host`, fall back to `-dc-ip`, fall back to `remote_name` from `parse_target`
2. Connect via `ldap://target` with NTLM auth (`login()`)
3. If `strongerAuthRequired` error, retry via `ldaps://target`
4. If `NTLMAuthNegotiate` error, log a message suggesting Kerberos authentication (`-k`)
5. If both `-dc-ip` and `-dc-host` are set and auth fails, log a message noting they must match
6. For Kerberos (`-k`), use `kerberosLogin()` instead
7. Derive `baseDN` from the domain (split on `.`, join as `DC=x,DC=y`)

LDAP connection and error-handling pattern from `GetADUsers.py` lines 136-173.

### Unlock Logic

For each target username (escape LDAP special characters `*`, `(`, `)`, `\`, NUL in the username before building the filter):

1. **Search** for the user via `LDAPConnection.search()` with filter `(sAMAccountName=<escaped_username>)`, requesting attributes `lockoutTime` and `userAccountControl`
2. **Extract DN** from the search result: `SearchResultEntry['objectName']` contains the full DN (e.g., `CN=jsmith,OU=Users,DC=corp,DC=local`), which is required for the modify request
3. **Check** if the account is actually locked (`lockoutTime > 0` means locked)
4. **Unlock** by sending an LDAP ModifyRequest setting `lockoutTime` to `0`:
   ```python
   modifyRequest = ModifyRequest()
   modifyRequest['object'] = userDN  # full DN from step 2
   modifyRequest['changes'][0]['operation'] = Operation('replace')
   modifyRequest['changes'][0]['modification']['type'] = 'lockoutTime'
   modifyRequest['changes'][0]['modification']['vals'].setComponentByPosition(0, '0')
   ```
   Send via `LDAPConnection.sendReceive(modifyRequest)`.
5. **Check the response**: `sendReceive()` returns a list of `LDAPMessage` objects. Extract the result via `message['protocolOp'].getComponent()` which yields a `ModifyResponse` (subclass of `LDAPResult`). Check `resultCode`:
   - `success` (0) → unlock succeeded
   - `insufficientAccessRights` (50) → permission denied
   - `noSuchObject` (32) → DN not found
   - Other → log the error code and diagnostic message
6. **Report** per-user: success, already-unlocked, user-not-found, or permission-denied

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

No other files are modified. The script is self-contained, depending only on `impacket`.

## Dependencies

All already installed on this system:

- `impacket 0.11.0` — target parsing, LDAP connection, logger, ASN1 types (including `ModifyRequest`/`ModifyResponse`)
- Python 3 standard library — `argparse`, `logging`, `sys`, `getpass`, `datetime`

## Execution Notes

**Executed: 2026-04-05**

Implemented as planned with no deviations. Single file `unlockAccount.py` (~230 lines).

- CLI: `parse_target` (smbclient-style), all auth/connection args match plan
- LDAP: impacket native `LDAPConnection` with NTLM/Kerberos and LDAPS fallback
- Unlock: raw `ModifyRequest` ASN1 via `sendReceive()` setting `lockoutTime=0`
- LDAP filter escaping for special characters in usernames
- User file supports comments (`#`) and blank lines
- Summary line at end: unlocked / skipped / errors

**Commit:** `5998f3d` — Add unlockAccount.py — AD account unlocker via LDAP
