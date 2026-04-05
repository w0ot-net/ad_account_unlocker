<!-- Review 2 completed: 2026-04-05 -->
# Plan: Report Currently Locked AD Accounts

## Summary

Add a `-list` flag to `unlockAccount.py` that queries Active Directory and reports all currently locked-out user accounts. It will query the domain's lockout policy to determine which accounts are still within the lockout window versus those whose lockout has naturally expired, and display results in a formatted table with lockout timestamps.

## Problem

When investigating account lockouts or preparing to do bulk unlocks, there is no way to discover which accounts are currently locked without switching to a separate tool or GUI. The unlock tool should be able to answer "what's locked?" before "unlock this."

## Goal

After implementation, a user can run:

```
python3 unlockAccount.py domain/admin:Password123@dc01.corp.local -list
```

And see a table of all currently locked accounts with their lockout times. The flag is mutually exclusive with `-user` / `-user-file` — it's a query-only mode.

## Design

### CLI Change

Add one new argument to the existing argparse setup:

- **`-list`**: `action='store_true'` — query and display all currently locked accounts, then exit

Validation logic:
- If `-list` is specified, `-user` and `-user-file` must NOT be specified (and vice versa)
- If none of `-list`, `-user`, or `-user-file` is specified, print help and exit

### Lockout Detection Logic

AD lockout is not a simple boolean. A `lockoutTime > 0` does NOT mean the account is currently locked — the lockout may have expired based on the domain's lockout duration policy. To report accurately:

1. **Query domain lockout policy**: Search the domain root DN (baseDN) with `scope=Scope('baseObject')` for attribute `lockoutDuration`. The `baseObject` scope is required because `lockoutDuration` is an attribute on the domain root object itself — the default `wholeSubtree` scope would search every object in the domain, which is expensive and wrong.
   - `lockoutDuration` is stored as a negative FILETIME interval (100-nanosecond units)
   - Example: `-18000000000` = 30 minutes
   - If `lockoutDuration = 0`, accounts stay locked until manually unlocked (no auto-expiry)

2. **Query all users with non-zero lockoutTime**: LDAP filter:
   ```
   (&(objectCategory=person)(objectClass=user)(lockoutTime>=1))
   ```
   Attributes: `sAMAccountName`, `lockoutTime`

3. **Filter to currently locked**: For each result, compute whether the lockout is still active. Compare in FILETIME space (convert to datetime only for display):
   ```python
   now_ft = datetime_to_filetime(datetime.utcnow())
   still_locked = lockout_time + abs(lockout_duration) > now_ft
   ```
   - If `lockoutDuration == 0`: always locked (until admin unlocks)
   - Otherwise: locked if `lockoutTime + abs(lockoutDuration) > now_ft`

4. **Display**: Print a formatted table:
   ```
   [*] Querying domain lockout policy...
   [*] Lockout duration: 30 minutes
   [*] Searching for locked accounts in DC=corp,DC=local...

   sAMAccountName       Locked Since              Expires
   -------------------- ------------------------- -------------------------
   jsmith               2026-04-05 10:23:45       2026-04-05 10:53:45
   testuser             2026-04-05 09:01:12       2026-04-05 09:31:12

   [*] 2 account(s) currently locked out.
   ```

   If `lockoutDuration == 0` (permanent until unlocked), the Expires column shows `Never (manual unlock required)`.

   If no accounts are currently locked, skip the table header and print:
   ```
   [*] No accounts currently locked out.
   ```

### FILETIME Conversion

Windows FILETIME is 100-nanosecond intervals since 1601-01-01. Python `datetime` uses Unix epoch (1970-01-01). The offset between them is `116444736000000000` (in 100ns units). Conversion:

```python
FILETIME_UNIX_OFFSET = 116444736000000000  # 100ns intervals between 1601-01-01 and 1970-01-01

def filetime_to_datetime(ft):
    """Convert Windows FILETIME to a local-time datetime, matching GetADUsers.py behavior."""
    unix_ts = (ft - FILETIME_UNIX_OFFSET) / 10_000_000
    return datetime.fromtimestamp(unix_ts)

def datetime_to_filetime(dt):
    """Convert a UTC datetime to Windows FILETIME (for lockout expiry comparison)."""
    delta = dt - datetime(1601, 1, 1)
    return int(delta.total_seconds() * 10_000_000)
```

`filetime_to_datetime` uses `datetime.fromtimestamp()` (local time), the standard impacket convention for displaying AD timestamps. `datetime_to_filetime` operates in UTC — use `datetime.utcnow()` when computing `now_ft` for the lockout expiry comparison.

### Paged Results

Use `SimplePagedResultsControl` (page size 100) for the locked-users search (step 2) to handle domains with many users. The domain root policy query (step 1, `baseObject` scope) returns a single object and does not need paging.

## Affected Components

- `unlockAccount.py` (new — planned in `ad-account-unlocker.md`): Add `-list` flag, lockout policy query, locked-account search with FILETIME comparison, and formatted table output. Adds ~60 lines to the planned ~200.

## Execution Notes

**Executed: 2026-04-05**

Implemented as planned with no deviations:

- Added `-list` flag with mutual exclusion validation against `-user`/`-user-file`
- `listLocked()` method: queries `lockoutDuration` from domain root (baseObject scope), then searches all users with `lockoutTime>=1` using paged results
- FILETIME conversion helpers (`filetime_to_datetime`, `datetime_to_filetime`) for lockout timestamp comparison and display
- Filters results to currently-locked accounts by comparing `lockoutTime + abs(lockoutDuration) > now`
- Formatted table output with sAMAccountName, Locked Since, Expires columns
- Handles permanent lockout policy (`lockoutDuration=0`) with "Never (manual unlock required)"

**Commit:** `f704423` — Add -list flag to report currently locked AD accounts
