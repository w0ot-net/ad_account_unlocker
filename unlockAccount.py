#!/usr/bin/env python3
# AD Account Unlocker — Impacket-Style CLI Tool
#
# Unlocks locked-out Active Directory accounts by resetting lockoutTime to 0 via LDAP.
# Uses the same credential/connection arguments as impacket example tools.
#
# Usage:
#   python3 unlockAccount.py [[domain/]username[:password]@]<dc> -user <sAMAccountName>
#   python3 unlockAccount.py [[domain/]username[:password]@]<dc> -user-file <file>

from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
import argparse
import logging
import sys

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldapasn1 import ModifyRequest, Operation, ResultCode, SearchResultEntry
from impacket.smbconnection import SMBConnection, SessionError


def ldap_escape(s):
    """Escape special characters for LDAP filter values (RFC 4515)."""
    s = s.replace('\\', '\\5c')
    s = s.replace('*', '\\2a')
    s = s.replace('(', '\\28')
    s = s.replace(')', '\\29')
    s = s.replace('\x00', '\\00')
    return s


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

        # Build baseDN from domain
        domainParts = self.__domain.split('.')
        self.baseDN = ','.join('dc=%s' % part for part in domainParts)

    def getMachineName(self, target):
        try:
            s = SMBConnection(target, target)
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
        else:
            if self.__kdcIP is not None:
                target = self.__kdcIP
            else:
                target = self.__remoteHost

            if self.__doKerberos:
                logging.info('Getting machine hostname')
                target = self.getMachineName(target)

        logging.info('Connecting to %s via LDAP' % target)

        try:
            ldapConnection = ldap.LDAPConnection('ldap://%s' % target, self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                             self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if 'strongerAuthRequired' in str(e):
                logging.info('LDAP requires SSL, retrying with LDAPS')
                ldapConnection = ldap.LDAPConnection('ldaps://%s' % target, self.baseDN, self.__kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain,
                                                 self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if 'NTLMAuthNegotiate' in str(e):
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. "
                                     "Try to use Kerberos authentication instead (-k).")
                elif self.__kdcIP is not None and self.__kdcHost is not None:
                    logging.critical("If the credentials are valid, check the hostname and IP address of KDC. "
                                     "They must match exactly each other.")
                raise

        return ldapConnection

    def findUser(self, ldapConnection, username):
        """Search for a user by sAMAccountName. Returns (dn, lockoutTime) or (None, None) if not found."""
        escapedUser = ldap_escape(username)
        searchFilter = '(sAMAccountName=%s)' % escapedUser

        try:
            results = ldapConnection.search(
                searchFilter=searchFilter,
                attributes=['lockoutTime', 'userAccountControl'],
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

    def run(self, users):
        ldapConnection = self.connect()
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
        ldapConnection.close()


def main():
    print(version.BANNER)

    parser = argparse.ArgumentParser(
        add_help=True,
        description='Unlock locked Active Directory accounts via LDAP.'
    )

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

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

    # Init the example's logger theme
    logger.init(options.ts)

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Validate that at least one target user option is provided
    if options.user is None and options.user_file is None:
        logging.critical('Either -user or -user-file must be specified')
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

    # Store remote_host for the class to use
    options.remote_host = remote_host

    # Build the list of users to unlock
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

    try:
        unlocker = AccountUnlocker(username, password, domain, options)
        unlocker.run(users)
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))


if __name__ == '__main__':
    main()
