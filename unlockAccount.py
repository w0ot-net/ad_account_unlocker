#!/usr/bin/env python3
# AD Account Unlocker — Impacket-Style CLI Tool
#
# Unlocks locked-out Active Directory accounts by resetting lockoutTime to 0 via LDAP.
# Uses the same credential/connection arguments as impacket example tools.
#
# Usage:
#   python3 unlockAccount.py [[domain/]username[:password]@]<dc> -user <sAMAccountName>
#   python3 unlockAccount.py [[domain/]username[:password]@]<dc> -user-file <file>
#   python3 unlockAccount.py [[domain/]username[:password]@]<dc> -list

import argparse
import logging
import sys
from datetime import datetime

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from ldap3.utils.conv import escape_filter_chars
from impacket.ldap import ldap
from impacket.ldap.ldapasn1 import ModifyRequest, Operation, Scope, SearchResultEntry, SimplePagedResultsControl
from impacket.smbconnection import SMBConnection, SessionError


FILETIME_UNIX_OFFSET = 116444736000000000  # 100ns intervals between 1601-01-01 and 1970-01-01


def filetime_to_datetime(ft):
    """Convert Windows FILETIME to local-time datetime."""
    return datetime.fromtimestamp((ft - FILETIME_UNIX_OFFSET) / 10_000_000)


def datetime_to_filetime(dt):
    """Convert UTC datetime to Windows FILETIME."""
    delta = dt - datetime(1601, 1, 1)
    return int(delta.total_seconds() * 10_000_000)


class AccountUnlocker:
    def __init__(self, username, password, domain, options):
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        self.__aesKey = options.aesKey
        self.__doKerberos = options.k
        self.__kdcIP = options.dc_ip
        self.__kdcHost = options.dc_host
        self.__remoteHost = options.remote_host

        if options.hashes is not None:
            self.__lmhash, self.__nthash = options.hashes.split(':')

        domainParts = self.__domain.split('.')
        self.baseDN = ','.join('dc=%s' % part for part in domainParts)

    def _getMachineName(self, target):
        s = SMBConnection(target, target)
        try:
            s.login('', '')
        except OSError as e:
            if 'timed out' in str(e):
                raise Exception('The connection timed out. Probably 445/TCP port is closed. '
                                'Try to specify corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            raise
        except SessionError as e:
            if 'STATUS_NOT_SUPPORTED' in str(e):
                raise Exception('The SMB request is not supported. Probably NTLM is disabled. '
                                'Try to specify corresponding NetBIOS name or FQDN as the value of the -dc-host option')
            raise
        except Exception:
            if s.getServerName() == '':
                raise Exception('Error while anonymous logging into %s' % target)
        else:
            s.logoff()
        return s.getServerName()

    def connect(self):
        """Establish LDAP connection and return it."""
        if self.__kdcHost is not None:
            target = self.__kdcHost
        elif self.__kdcIP is not None:
            target = self.__kdcIP
        else:
            target = self.__remoteHost

        if self.__kdcHost is None and self.__doKerberos:
            logging.info('Getting machine hostname')
            target = self._getMachineName(target)

        logging.info('Connecting to %s via LDAP' % target)

        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcIP)
            self._login(ldapConnection)
        except ldap.LDAPSessionError as e:
            if 'strongerAuthRequired' in str(e):
                logging.info('LDAP requires SSL, retrying with LDAPS')
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcIP)
                self._login(ldapConnection)
            elif 'NTLMAuthNegotiate' in str(e):
                logging.critical("NTLM negotiation failed. Probably NTLM is disabled. "
                                 "Try to use Kerberos authentication instead (-k).")
                raise
            else:
                if self.__kdcIP is not None and self.__kdcHost is not None:
                    logging.critical("If the credentials are valid, check the hostname and IP address of KDC. "
                                     "They must match exactly each other.")
                raise

        return ldapConnection

    def _login(self, ldapConnection):
        """Authenticate to the given LDAP connection using NTLM or Kerberos."""
        if self.__doKerberos is not True:
            ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        else:
            ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                         self.__lmhash, self.__nthash,
                                         self.__aesKey, kdcHost=self.__kdcIP)

    def findUser(self, ldapConnection, username):
        """Search for a user by sAMAccountName. Returns (dn, lockoutTime) or (None, None) if not found."""
        escapedUser = escape_filter_chars(username)
        searchFilter = '(sAMAccountName=%s)' % escapedUser

        try:
            results = ldapConnection.search(
                searchFilter=searchFilter,
                attributes=['lockoutTime'],
                sizeLimit=0
            )
        except ldap.LDAPSearchError as e:
            logging.error('LDAP search error for %s: %s' % (username, str(e)))
            return None, None

        for item in results:
            if not isinstance(item, SearchResultEntry):
                continue

            userDN = str(item['objectName'])
            lockoutTime = 0

            for attribute in item['attributes']:
                if str(attribute['type']) == 'lockoutTime':
                    lockoutTime = int(str(attribute['vals'][0]))

            return userDN, lockoutTime

        return None, None

    def unlockUser(self, ldapConnection, userDN):
        """Send LDAP modify to set lockoutTime=0. Returns (success, error_message)."""
        modifyRequest = ModifyRequest()
        modifyRequest['object'] = userDN
        modifyRequest['changes'][0]['operation'] = Operation('replace')
        modifyRequest['changes'][0]['modification']['type'] = 'lockoutTime'
        modifyRequest['changes'][0]['modification']['vals'].setComponentByPosition(0, '0')

        try:
            response = ldapConnection.sendReceive(modifyRequest)
        except Exception as e:
            return False, str(e)

        for message in response:
            result = message['protocolOp'].getComponent()
            resultCode = int(result['resultCode'])

            if resultCode == 0:
                return True, None
            else:
                diag = str(result['diagnosticMessage'])
                code_name = result['resultCode'].prettyPrint()
                return False, '%s: %s' % (code_name, diag)

        return False, 'No response received'

    def listLocked(self):
        """Query and display all currently locked accounts."""
        ldapConnection = self.connect()
        try:
            logging.info('Querying domain lockout policy...')
            results = ldapConnection.search(
                searchBase=self.baseDN,
                scope=Scope('baseObject'),
                searchFilter='(objectClass=*)',
                attributes=['lockoutDuration'],
                sizeLimit=0
            )

            lockoutDuration = 0
            for item in results:
                if not isinstance(item, SearchResultEntry):
                    continue
                for attribute in item['attributes']:
                    if str(attribute['type']) == 'lockoutDuration':
                        lockoutDuration = int(str(attribute['vals'][0]))

            if lockoutDuration == 0:
                logging.info('Lockout duration: accounts stay locked until manually unlocked')
            else:
                minutes = abs(lockoutDuration) // 10_000_000 // 60
                logging.info('Lockout duration: %d minutes' % minutes)

            logging.info('Searching for locked accounts in %s...' % self.baseDN)
            sc = SimplePagedResultsControl(size=100)
            results = ldapConnection.search(
                searchFilter='(&(objectCategory=person)(objectClass=user)(lockoutTime>=1))',
                attributes=['sAMAccountName', 'lockoutTime'],
                sizeLimit=0,
                searchControls=[sc]
            )

            now_ft = datetime_to_filetime(datetime.utcnow())
            locked_accounts = []

            for item in results:
                if not isinstance(item, SearchResultEntry):
                    continue

                sAMAccountName = ''
                lockoutTime = 0

                for attribute in item['attributes']:
                    attr_type = str(attribute['type'])
                    if attr_type == 'sAMAccountName':
                        sAMAccountName = attribute['vals'][0].asOctets().decode('utf-8')
                    elif attr_type == 'lockoutTime':
                        lockoutTime = int(str(attribute['vals'][0]))

                if lockoutTime == 0:
                    continue

                # Check if lockout is still active
                if lockoutDuration == 0:
                    still_locked = True
                else:
                    still_locked = lockoutTime + abs(lockoutDuration) > now_ft

                if still_locked:
                    locked_accounts.append((sAMAccountName, lockoutTime))

            if not locked_accounts:
                logging.info('No accounts currently locked out.')
                return

            col_name = 20
            col_since = 25
            col_expires = 25
            header = '{0:<{w0}} {1:<{w1}} {2:<{w2}}'.format(
                'sAMAccountName', 'Locked Since', 'Expires',
                w0=col_name, w1=col_since, w2=col_expires)
            separator = '{0} {1} {2}'.format('-' * col_name, '-' * col_since, '-' * col_expires)

            print(header)
            print(separator)

            for sAMAccountName, lockoutTime in locked_accounts:
                locked_since = str(filetime_to_datetime(lockoutTime))[:19]

                if lockoutDuration == 0:
                    expires = 'Never (manual unlock required)'
                else:
                    expires_ft = lockoutTime + abs(lockoutDuration)
                    expires = str(filetime_to_datetime(expires_ft))[:19]

                print('{0:<{w0}} {1:<{w1}} {2:<{w2}}'.format(
                    sAMAccountName, locked_since, expires,
                    w0=col_name, w1=col_since, w2=col_expires))

            logging.info('%d account(s) currently locked out.' % len(locked_accounts))
        finally:
            ldapConnection.close()

    def run(self, users):
        ldapConnection = self.connect()
        try:
            logging.info('BaseDN: %s' % self.baseDN)

            unlocked = 0
            skipped = 0
            errors = 0

            for username in users:
                logging.info('Processing user: %s' % username)

                userDN, lockoutTime = self.findUser(ldapConnection, username)

                if userDN is None:
                    logging.error('  User not found: %s' % username)
                    errors += 1
                    continue

                if lockoutTime == 0:
                    logging.info('  lockoutTime: 0 (not locked)')
                    logging.info('  Account %s is not locked — skipping' % username)
                    skipped += 1
                    continue

                logging.info('  lockoutTime: %d (locked)' % lockoutTime)

                success, error_msg = self.unlockUser(ldapConnection, userDN)
                if success:
                    logging.info('  Successfully unlocked %s' % username)
                    unlocked += 1
                else:
                    logging.error('  Failed to unlock %s: %s' % (username, error_msg))
                    errors += 1

            logging.info('Done. %d account(s) unlocked, %d already unlocked, %d error(s).' % (unlocked, skipped, errors))
        finally:
            ldapConnection.close()


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True,
        description='Unlock locked Active Directory accounts via LDAP.'
    )

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    parser.add_argument('-list', action='store_true',
                        help='List all currently locked accounts and exit')

    group = parser.add_argument_group('target users')
    group.add_argument('-user', action='store', metavar='username',
                       help='sAMAccountName of the account to unlock')
    group.add_argument('-user-file', action='store', metavar='file',
                       help='File containing sAMAccountNames to unlock (one per line)')

    parser.add_argument('-ts', action='store_true', help='Adds timestamp to every logging output')
    parser.add_argument('-debug', action='store_true', help='Turn DEBUG output ON')

    group = parser.add_argument_group('authentication')
    group.add_argument('-hashes', action='store', metavar='LMHASH:NTHASH',
                       help='NTLM hashes, format is LMHASH:NTHASH')
    group.add_argument('-no-pass', action='store_true',
                       help="don't ask for password (useful for -k)")
    group.add_argument('-k', action='store_true',
                       help='Use Kerberos authentication. Grabs credentials from ccache file '
                            '(KRB5CCNAME) based on target parameters. If valid credentials '
                            'cannot be found, it will use the ones specified in the command line')
    group.add_argument('-aesKey', action='store', metavar='hex key',
                       help='AES key to use for Kerberos Authentication (128 or 256 bits)')

    group = parser.add_argument_group('connection')
    group.add_argument('-dc-ip', action='store', metavar='ip address',
                       help='IP Address of the domain controller. If omitted it will use the domain part (FQDN) '
                            'specified in the target parameter')
    group.add_argument('-dc-host', action='store', metavar='hostname',
                       help='Hostname of the domain controller to use. If omitted, the domain part (FQDN) '
                            'specified in the target parameter will be used')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    if options.list and (options.user is not None or options.user_file is not None):
        logging.critical('-list cannot be used with -user or -user-file')
        sys.exit(1)

    if not options.list and options.user is None and options.user_file is None:
        logging.critical('Either -list, -user, or -user-file must be specified')
        sys.exit(1)

    domain, username, password, remote_host = parse_target(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aesKey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aesKey is not None:
        options.k = True

    options.remote_host = remote_host

    try:
        unlocker = AccountUnlocker(username, password, domain, options)

        if options.list:
            unlocker.listLocked()
        else:
            users = []
            if options.user is not None:
                users.append(options.user)

            if options.user_file is not None:
                try:
                    with open(options.user_file, 'r') as f:
                        for line in f:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                users.append(line)
                except IOError as e:
                    logging.critical('Error reading user file: %s' % str(e))
                    sys.exit(1)

            if len(users) == 0:
                logging.critical('No users to process')
                sys.exit(1)

            unlocker.run(users)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
