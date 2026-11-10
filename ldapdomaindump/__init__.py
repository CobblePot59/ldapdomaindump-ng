####################
#
# Copyright (c) 2017 Dirk-jan Mollema
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################
import sys, os, re, codecs, json, argparse, getpass, base64
# import class and constants
from datetime import datetime, timedelta
from urllib.parse import quote_plus
import ldap3
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM
from ldap3.core.exceptions import LDAPKeyError, LDAPAttributeError, LDAPCursorError, LDAPInvalidDnError, LDAPSocketOpenError
from ldap3.abstract import attribute, attrDef
from ldap3.utils import dn
from ldap3.protocol.formatters.formatters import format_sid

# dnspython, for resolving hostnames
import dns.resolver

from ldapdomaindump.extra import ExtraCollector, ENCTYPE_FLAGS, rdn_value, parse_sd_sids, split_dn, dn_key


# User account control flags
# From: https://blogs.technet.microsoft.com/askpfeplat/2014/01/15/understanding-the-useraccountcontrol-attribute-in-active-directory/
uac_flags = {'ACCOUNT_DISABLED':0x00000002,
             'ACCOUNT_LOCKED':0x00000010,
             'PASSWD_NOTREQD':0x00000020,
             'PASSWD_CANT_CHANGE': 0x00000040,
             'PASSWORD_STORE_CLEARTEXT': 0x00000080,
             'NORMAL_ACCOUNT': 0x00000200,
             'WORKSTATION_ACCOUNT':0x00001000,
             'SERVER_TRUST_ACCOUNT': 0x00002000,
             'DONT_EXPIRE_PASSWD': 0x00010000,
             'SMARTCARD_REQUIRED': 0x00040000,
             'TRUSTED_FOR_DELEGATION': 0x00080000,
             'NOT_DELEGATED': 0x00100000,
             'USE_DES_KEY_ONLY': 0x00200000,
             'DONT_REQ_PREAUTH': 0x00400000,
             'PASSWORD_EXPIRED': 0x00800000,
             'TRUSTED_TO_AUTH_FOR_DELEGATION': 0x01000000,
             'PARTIAL_SECRETS_ACCOUNT': 0x04000000
            }

# Password policy flags
pwd_flags = {'PASSWORD_COMPLEX':0x01,
             'PASSWORD_NO_ANON_CHANGE': 0x02,
             'PASSWORD_NO_CLEAR_CHANGE': 0x04,
             'LOCKOUT_ADMINS': 0x08,
             'PASSWORD_STORE_CLEARTEXT': 0x10,
             'REFUSE_PASSWORD_CHANGE': 0x20}

# Special AD interval value (0x8000000000000000) meaning "never" / "forever"
AD_INTERVAL_NEVER = -9223372036854775808

# Flags highlighted in the HTML report (security relevant ones in red)
flag_severity = {'DONT_REQ_PREAUTH': ' danger',
                 'PASSWD_NOTREQD': ' danger',
                 'PASSWORD_STORE_CLEARTEXT': ' danger',
                 'USE_DES_KEY_ONLY': ' danger',
                 'TRUSTED_FOR_DELEGATION': ' danger',
                 'TRUSTED_TO_AUTH_FOR_DELEGATION': ' danger',
                 'NO_COMPLEXITY': ' danger',
                 'DONT_EXPIRE_PASSWD': ' warn',
                 'ACCOUNT_LOCKED': ' warn',
                 'PASSWORD_EXPIRED': ' warn',
                 'PASSWD_CANT_CHANGE': ' warn',
                 'SMARTCARD_REQUIRED': ' ok',
                 'NOT_DELEGATED': ' ok',
                 'PASSWORD_COMPLEX': ' ok',
                 'LOCKOUT_ADMINS': ' ok'}

# Domain trust flags
# From: https://msdn.microsoft.com/en-us/library/cc223779.aspx
trust_flags = {'NON_TRANSITIVE':0x00000001,
               'UPLEVEL_ONLY':0x00000002,
               'QUARANTINED_DOMAIN':0x00000004,
               'FOREST_TRANSITIVE':0x00000008,
               'CROSS_ORGANIZATION':0x00000010,
               'WITHIN_FOREST':0x00000020,
               'TREAT_AS_EXTERNAL':0x00000040,
               'USES_RC4_ENCRYPTION':0x00000080,
               'CROSS_ORGANIZATION_NO_TGT_DELEGATION':0x00000200,
               'CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION':0x00000800,
               'PIM_TRUST':0x00000400}

# Domain trust direction
# From: https://msdn.microsoft.com/en-us/library/cc223768.aspx
trust_directions = {'INBOUND':0x01,
                    'OUTBOUND':0x02,
                    'BIDIRECTIONAL':0x03}
# Domain trust types
trust_type = {'DOWNLEVEL':0x01,
              'UPLEVEL':0x02,
              'MIT':0x03}

# Common attribute pretty translations
attr_translations = {'sAMAccountName':'SAM Name',
                     'cn':'CN',
                     'operatingSystem':'Operating System',
                     'operatingSystemServicePack':'Service Pack',
                     'operatingSystemVersion':'OS Version',
                     'userAccountControl':'Flags',
                     'objectSid':'SID',
                     'memberOf':'Member of groups',
                     'primaryGroupId':'Primary group',
                     'dNSHostName':'DNS Hostname',
                     'whenCreated':'Created on',
                     'whenChanged':'Changed on',
                     'IPv4':'IPv4 Address',
                     'lockOutObservationWindow':'Lockout time window',
                     'lockoutDuration':'Lockout Duration',
                     'lockoutThreshold':'Lockout Threshold',
                     'maxPwdAge':'Max password age',
                     'minPwdAge':'Min password age',
                     'minPwdLength':'Min password length',
                     'pwdHistoryLength':'Password history length',
                     'pwdProperties':'Password properties',
                     'ms-DS-MachineAccountQuota':'Machine Account Quota',
                     'flatName':'NETBIOS Domain name',
                     'name':'Name',
                     'description':'Description',
                     'lastLogon':'Last logon',
                     'pwdLastSet':'Password last set',
                     'servicePrincipalName':'SPN',
                     'distinguishedName':'Distinguished name',
                     'securityIdentifier':'SID',
                     'trustAttributes':'Trust attributes',
                     'trustDirection':'Direction',
                     'trustType':'Trust type',
                     'userPrincipalName':'UPN',
                     'mail':'Mail',
                     'title':'Title',
                     'department':'Department',
                     'manager':'Manager',
                     'managedBy':'Managed by',
                     'lastLogonTimestamp':'Last logon (replicated)',
                     'accountExpires':'Account expires',
                     'adminCount':'adminCount',
                     'msDS-SupportedEncryptionTypes':'Encryption types',
                     'msDS-AllowedToDelegateTo':'Allowed to delegate to',
                     'msDS-AllowedToActOnBehalfOfOtherIdentity':'Allowed to act on behalf (RBCD)',
                     'location':'Location',
                     'LAPS':'LAPS'}

#Attributes added to the reports, appended so the greppable column order stays compatible
EXTRA_USERATTRIBUTES = ['userPrincipalName', 'mail', 'title', 'department', 'manager', 'lastLogonTimestamp', 'accountExpires', 'adminCount', 'msDS-SupportedEncryptionTypes', 'msDS-AllowedToDelegateTo']
EXTRA_COMPUTERATTRIBUTES = ['lastLogonTimestamp', 'location', 'msDS-SupportedEncryptionTypes', 'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity', 'LAPS']
EXTRA_GROUPATTRIBUTES = ['adminCount', 'managedBy']
#LAPS expiration attributes (the password itself is never requested)
LAPS_ATTRIBUTES = {'ms-Mcs-AdmPwdExpirationTime': 'Legacy LAPS', 'msLAPS-PasswordExpirationTime': 'Windows LAPS'}

#Columns hidden by default in the HTML tables (they can be shown with the Columns menu)
HTML_HIDDEN_COLUMNS = {'name', 'whenChanged', 'mail', 'title', 'department', 'manager', 'accountExpires',
                       'msDS-SupportedEncryptionTypes', 'operatingSystemServicePack', 'location', 'managedBy'}

MINIMAL_COMPUTERATTRIBUTES = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid', 'description', 'objectClass', 'memberOf', 'primaryGroupId', 'servicePrincipalName', 'distinguishedName'] + EXTRA_COMPUTERATTRIBUTES[:-1] + list(LAPS_ATTRIBUTES)
MINIMAL_USERATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName', 'objectClass', 'distinguishedName'] + EXTRA_USERATTRIBUTES
MINIMAL_GROUPATTRIBUTES = ['cn', 'name', 'sAMAccountName', 'memberOf', 'description', 'whenCreated', 'whenChanged', 'objectSid', 'distinguishedName', 'objectClass'] + EXTRA_GROUPATTRIBUTES

#Class containing the default config
class domainDumpConfig():
    def __init__(self):
        #Base path
        self.basepath = '.'

        #Output files basenames
        self.groupsfile = 'domain_groups' #Groups
        self.usersfile = 'domain_users' #User accounts
        self.computersfile = 'domain_computers' #Computer accounts
        self.policyfile = 'domain_policy' #General domain attributes
        self.trustsfile = 'domain_trusts' #Domain trusts attributes

        #Combined files basenames
        self.users_by_group = 'domain_users_by_group' #Users sorted by group
        self.computers_by_os = 'domain_computers_by_os' #Computers sorted by OS

        #Additional reports basenames
        self.indexfile = 'index' #Overview (HTML only)
        self.domainfile = 'domain_info' #Domain/forest information, DCs, FSMO, sites
        self.ousfile = 'domain_ous' #Organizational units tree
        self.gposfile = 'domain_gpos' #Group policy objects
        self.dnsfile = 'domain_dns' #AD integrated DNS records
        self.pkifile = 'domain_pki' #Certificate authorities and templates
        self.servicesfile = 'domain_services' #Managed service accounts and SPNs
        self.contactsfile = 'domain_contacts' #Contacts
        self.foreignfile = 'domain_foreign' #Foreign security principals
        self.orgchartfile = 'domain_orgchart' #Organization chart (HTML only)
        self.membershipfile = 'domain_membership' #Group membership explorer (HTML only)

        #Write a single file per output format instead of one file per report
        self.singlefile = False
        self.singlefilename = 'domain_dump'

        #Output formats
        self.outputhtml = True
        self.outputjson = True
        self.outputgrep = True

        #Output json for groups
        self.groupedjson = False

        #Default field delimiter for greppable format is a tab
        self.grepsplitchar = '\t'

        #Other settings
        self.lookuphostnames = False #Look up hostnames of computers to get their IP address
        self.dnsserver = '' #Addres of the DNS server to use, if not specified default DNS will be used
        self.minimal = False #Only query minimal list of attributes

#Add a computed attribute to an ldap3 entry, so it can be used like a real one (and is exported to JSON)
def setCustomAttribute(entry, name, value):
    att = attribute.Attribute(attrDef.AttrDef(name), entry, None)
    att.__dict__['_response'] = value
    att.__dict__['raw_values'] = [value]
    att.__dict__['values'] = [value] if value not in (None, '') else []
    entry._state.attributes[name] = att

#Domaindumper main class
class domainDumper():
    def __init__(self, server, connection, config, root=None):
        self.server = server
        self.connection = connection
        self.config = config
        #Unless the root is specified we get it from the server
        if root is None:
            self.root = self.getRoot()
        else:
            self.root = root
        self.users = None #Domain users
        self.groups = None #Domain groups
        self.computers = None #Domain computers
        self.policy = None #Domain policy
        self.groups_dnmap = None #CN map for group IDs to CN
        self.groups_dict = None #Dictionary of groups by CN
        self.trusts = None #Domain trusts

    #Keep only the attributes known by the server schema (ldap3 rejects unknown attribute names)
    def schemaAttributes(self, names):
        if self.server.schema is None:
            return names
        return [a for a in names if a in self.server.schema.attribute_types]

    #Get the server root from the default naming context
    def getRoot(self):
        return self.server.info.other['defaultNamingContext'][0]

    #Query the groups of the current user
    def getCurrentUserGroups(self, username, domainsid=None):
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))' % username, attributes=['cn', 'memberOf', 'primaryGroupId'])
        try:
            groups = self.connection.entries[0]['memberOf'].values
            if domainsid is not None:
                groups.append(self.getGroupDNfromID(domainsid, self.connection.entries[0]['primaryGroupId'].value))
            return groups
        except LDAPKeyError:
            #No groups, probably just member of the primary group
            if domainsid is not None:
                primarygroup = self.getGroupDNfromID(domainsid, self.connection.entries[0]['primaryGroupId'].value)
                return [primarygroup]
            else:
                return []
        except IndexError:
            #The username does not exist (might be a computer account)
            return []

    #Check if the user is part of the Domain Admins or Enterprise Admins group, or any of their subgroups
    def isDomainAdmin(self, username):
        domainsid = self.getRootSid()
        groups = self.getCurrentUserGroups(username, domainsid)
        #Get DA and EA group DNs
        dagroupdn = self.getDAGroupDN(domainsid)
        eagroupdn = self.getEAGroupDN(domainsid)
        #First, simple checks
        for group in groups:
            if 'CN=Administrators' in group or 'CN=Domain Admins' in group or dagroupdn == group:
                return True
            #Also for enterprise admins if applicable
            if 'CN=Enterprise Admins' in group or (eagroupdn is not False and eagroupdn == group):
                return True
        #Now, just do a recursive check in both groups and their subgroups using LDAP_MATCHING_RULE_IN_CHAIN
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))' % (username, dagroupdn), attributes=['cn', 'sAMAccountName'])
        if len(self.connection.entries) > 0:
            return True
        self.connection.search(self.root, '(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s)(memberOf:1.2.840.113556.1.4.1941:=%s))' % (username, eagroupdn), attributes=['cn', 'sAMAccountName'])
        if len(self.connection.entries) > 0:
            return True
        #At last, check the users primary group ID
        return False

    #Get all users
    def getAllUsers(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectCategory=person)(objectClass=user))', attributes=self.schemaAttributes(MINIMAL_USERATTRIBUTES), paged_size=500, generator=False)
        else:
            self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectCategory=person)(objectClass=user))', attributes=ldap3.ALL_ATTRIBUTES, paged_size=500, generator=False)
        return self.connection.entries

    #Get all computers in the domain
    def getAllComputers(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectClass=computer)(objectClass=user))', attributes=self.schemaAttributes(MINIMAL_COMPUTERATTRIBUTES), paged_size=500, generator=False)
        else:
            self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectClass=computer)(objectClass=user))', attributes=ldap3.ALL_ATTRIBUTES, paged_size=500, generator=False)
        return self.connection.entries

    #Get all user SPNs
    def getAllUserSpns(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))', attributes=self.schemaAttributes(MINIMAL_USERATTRIBUTES), paged_size=500, generator=False)
        else:
            self.connection.extend.standard.paged_search('%s' % (self.root), '(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))', attributes=ldap3.ALL_ATTRIBUTES, paged_size=500, generator=False)
        return self.connection.entries

    #Get all defined groups
    def getAllGroups(self):
        if self.config.minimal:
            self.connection.extend.standard.paged_search(self.root, '(objectClass=group)', attributes=self.schemaAttributes(MINIMAL_GROUPATTRIBUTES), paged_size=500, generator=False)
        else:
            self.connection.extend.standard.paged_search(self.root, '(objectClass=group)', attributes=ldap3.ALL_ATTRIBUTES, paged_size=500, generator=False)
        return self.connection.entries

    #Get the domain policies (such as lockout policy)
    def getDomainPolicy(self):
        self.connection.search(self.root, '(objectClass=domain)', attributes=ldap3.ALL_ATTRIBUTES)
        return self.connection.entries

    #Get domain trusts
    def getTrusts(self):
        self.connection.search(self.root, '(objectClass=trustedDomain)', attributes=ldap3.ALL_ATTRIBUTES)
        return self.connection.entries

    #Get all defined security groups
    #Syntax from:
    #https://ldapwiki.willeke.com/wiki/Active%20Directory%20Group%20Related%20Searches
    def getAllSecurityGroups(self):
        self.connection.search(self.root, '(groupType:1.2.840.113556.1.4.803:=2147483648)', attributes=ldap3.ALL_ATTRIBUTES)
        return self.connection.entries

    #Get the SID of the root object
    def getRootSid(self):
        self.connection.search(self.root, '(objectClass=domain)', attributes=['objectSid'])
        try:
            sid = self.connection.entries[0].objectSid
        except (LDAPAttributeError, LDAPCursorError, IndexError):
            return False
        return sid

    #Get group members recursively using LDAP_MATCHING_RULE_IN_CHAIN (1.2.840.113556.1.4.1941)
    def getRecursiveGroupmembers(self, groupdn):
        self.connection.extend.standard.paged_search(self.root, '(&(objectCategory=person)(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:=%s))' % groupdn, attributes=self.schemaAttributes(MINIMAL_USERATTRIBUTES), paged_size=500, generator=False)
        return self.connection.entries

    #Resolve group ID to DN
    def getGroupDNfromID(self, domainsid, gid):
        self.connection.search(self.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['distinguishedName'])
        return self.connection.entries[0]['distinguishedName'].value

    #Get Domain Admins group DN
    def getDAGroupDN(self, domainsid):
        return self.getGroupDNfromID(domainsid, 512)

    #Get Enterprise Admins group DN
    def getEAGroupDN(self, domainsid):
        try:
            return self.getGroupDNfromID(domainsid, 519)
        except (LDAPAttributeError, LDAPCursorError, IndexError):
            #This does not exist, could be in a parent domain
            return False


    #Lookup all computer DNS names to get their IP
    def lookupComputerDnsNames(self):
        dnsresolver = dns.resolver.Resolver()
        dnsresolver.lifetime = 2
        if self.config.dnsserver != '':
            dnsresolver.nameservers = [self.config.dnsserver]
        for computer in self.computers:
            try:
                answers = dnsresolver.query(computer.dNSHostName.values[0], 'A')
                ip = str(answers.response.answer[0][0])
            except dns.resolver.NXDOMAIN:
                ip = 'error.NXDOMAIN'
            except dns.resolver.Timeout:
                ip = 'error.TIMEOUT'
            except (LDAPAttributeError, LDAPCursorError):
                ip = 'error.NOHOSTNAME'
            setCustomAttribute(computer, 'IPv4', ip)

    #Add a LAPS column telling which LAPS flavour (if any) manages the computer
    def tagLapsComputers(self):
        for computer in self.computers:
            laps = []
            for attr, label in LAPS_ATTRIBUTES.items():
                try:
                    if computer[attr].value is not None:
                        laps.append(label)
                except (LDAPKeyError, LDAPCursorError, LDAPAttributeError):
                    pass
            setCustomAttribute(computer, 'LAPS', ', '.join(laps))

    #Create a dictionary of all operating systems with the computer accounts that are associated
    def sortComputersByOS(self, items):
        osdict = {}
        for computer in items:
            try:
                cos = computer.operatingSystem.value or 'Unknown'
            except (LDAPAttributeError, LDAPCursorError):
                cos = 'Unknown'
            try:
                osdict[cos].append(computer)
            except KeyError:
                #New OS
                osdict[cos] = [computer]
        return osdict

    #Map all groups on their ID (taken from their SID) to CNs
    #This is used for getting the primary group of a user
    def mapGroupsIdsToDns(self):
        dnmap = {}
        for group in self.groups:
            gid = int(group.objectSid.value.split('-')[-1])
            dnmap[gid] = group.distinguishedName.values[0]
        self.groups_dnmap = dnmap
        return dnmap

    #Create a dictionary where a groups CN returns the full object
    def createGroupsDictByCn(self):
        gdict = {grp.cn.values[0]:grp for grp in self.groups}
        self.groups_dict = gdict
        return gdict

    #Get CN from DN
    def getGroupCnFromDn(self, dnin):
        cn = self.unescapecn(dn.parse_dn(dnin)[0][1])
        return cn

    #Unescape special DN characters from a CN (only needed if it comes from a DN)
    def unescapecn(self, cn):
        for c in ' "#+,;<=>\\\00':
            cn = cn.replace('\\'+c, c)
        return cn

    #Sort users by group they belong to
    def sortUsersByGroup(self, items):
        groupsdict = {}
        #Make sure the group CN mapping already exists
        if self.groups_dnmap is None:
            self.mapGroupsIdsToDns()
        for user in items:
            try:
                ugroups = [self.getGroupCnFromDn(group) for group in user.memberOf.values]
            #If the user is only in the default group, its memberOf property wont exist
            except (LDAPAttributeError, LDAPCursorError):
                ugroups = []
            #Add the user default group
            try:
                ugroups.append(self.getGroupCnFromDn(self.groups_dnmap[user.primaryGroupId.value]))
            # Sometimes we can't query this group or it doesn't exist
            except KeyError:
                pass
            for group in ugroups:
                try:
                    groupsdict[group].append(user)
                except KeyError:
                    #Group is not yet in dict
                    groupsdict[group] = [user]

        #Append any groups that are members of groups
        for group in self.groups:
            try:
                for parentgroup in group.memberOf.values:
                    try:
                        groupsdict[self.getGroupCnFromDn(parentgroup)].append(group)
                    except KeyError:
                        #Group is not yet in dict
                        groupsdict[self.getGroupCnFromDn(parentgroup)] = [group]
            #Without subgroups this attribute does not exist
            except (LDAPAttributeError, LDAPCursorError):
                pass

        return groupsdict

    #Main function
    def domainDump(self):
        self.users = self.getAllUsers()
        self.computers = self.getAllComputers()
        self.groups = self.getAllGroups()
        if self.config.lookuphostnames:
            self.lookupComputerDnsNames()
        #Copy the lists: the connection entries are replaced by every new search
        self.users = list(self.users)
        self.computers = list(self.computers)
        self.groups = list(self.groups)
        self.tagLapsComputers()
        self.policy = list(self.getDomainPolicy())
        self.trusts = list(self.getTrusts())
        self.extra = ExtraCollector(self).collect()
        rw = reportWriter(self.config)
        rw.writeReports(self)

#A report: one page in the HTML output and/or one JSON / greppable file
#html, json and grep are callables returning an iterable of text chunks (or None when the format is not available)
class Report():
    def __init__(self, name, title, label, html=None, json=None, grep=None, grouped=False, hasDisabled=False,
                 searchable=True, columns=False, csv=True, tree=False):
        self.name = name
        self.title = title
        self.label = label
        self.html = html
        self.json = json
        self.grep = grep
        self.grouped = grouped
        self.hasDisabled = hasDisabled
        self.searchable = searchable
        self.columns = columns
        self.csv = csv
        self.tree = tree

class reportWriter():
    def __init__(self, config):
        self.config = config
        self.dd = None
        if self.config.lookuphostnames:
            self.computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'IPv4', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid', 'description']
        else:
            self.computerattributes = ['cn', 'sAMAccountName', 'dNSHostName', 'operatingSystem', 'operatingSystemServicePack', 'operatingSystemVersion', 'lastLogon', 'userAccountControl', 'whenCreated', 'objectSid', 'description']
        self.computerattributes += EXTRA_COMPUTERATTRIBUTES
        self.userattributes = ['cn', 'name', 'sAMAccountName', 'memberOf', 'primaryGroupId', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName'] + EXTRA_USERATTRIBUTES
        #In grouped view, don't include the memberOf property to reduce output size
        self.userattributes_grouped = ['cn', 'name', 'sAMAccountName', 'whenCreated', 'whenChanged', 'lastLogon', 'userAccountControl', 'pwdLastSet', 'objectSid', 'description', 'servicePrincipalName'] + EXTRA_USERATTRIBUTES
        self.groupattributes = ['cn', 'sAMAccountName', 'memberOf', 'description', 'whenCreated', 'whenChanged', 'objectSid'] + EXTRA_GROUPATTRIBUTES
        self.policyattributes = ['distinguishedName', 'lockOutObservationWindow', 'lockoutDuration', 'lockoutThreshold', 'maxPwdAge', 'minPwdAge', 'minPwdLength', 'pwdHistoryLength', 'pwdProperties', 'ms-DS-MachineAccountQuota']
        self.trustattributes = ['cn', 'flatName', 'securityIdentifier', 'trustAttributes', 'trustDirection', 'trustType']
        #Static assets and metadata for the HTML reports
        if self.config.outputhtml:
            self.css = self.readPackageFile('style.css')
            self.js = self.readPackageFile('report.js')
        else:
            self.css = self.js = ''
        self.generated = datetime.now().strftime('%Y-%m-%d %H:%M')

    # ------------------------------------------------------------------
    # Generic helpers
    # ------------------------------------------------------------------

    #Escape HTML special chars
    def htmlescape(self, html):
        return (html.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;"))

    #Unescape special DN characters from a CN (only needed if it comes from a DN)
    def unescapecn(self, cn):
        for c in ' "#+,;<=>\\\00':
            cn = cn.replace('\\'+c, c)
        return cn

    #Convert an AD interval (negative number of 100 nanoseconds, or timedelta for ldap3 >= 2.6) to seconds
    #Returns None if the interval is the special "never" value (0x8000000000000000)
    def intervalToSeconds(self, length):
        if isinstance(length, timedelta):
            # ldap3 maps the "never" value to timedelta.max
            if length == timedelta.max:
                return None
            return abs(length.total_seconds())
        length = int(length)
        if length == AD_INTERVAL_NEVER:
            return None
        return abs(length) * .0000001

    #Convert password max age (in 100 nanoseconds), to days
    def nsToDays(self, length):
        seconds = self.intervalToSeconds(length)
        return float('inf') if seconds is None else seconds / 86400

    def nsToMinutes(self, length):
        seconds = self.intervalToSeconds(length)
        return float('inf') if seconds is None else seconds / 60

    #Human readable form of the interval attributes of the domain policy
    def formatPolicyInterval(self, aname, value):
        try:
            seconds = self.intervalToSeconds(value)
        except (TypeError, ValueError):
            return self.formatString(value)
        if aname == 'maxpwdage':
            #Both 0 and the minimum int64 value mean passwords never expire
            if seconds is None or seconds == 0:
                return 'Never expires'
            return '%.2f days' % (seconds / 86400)
        if aname == 'minpwdage':
            if seconds is None:
                return 'Never'
            return '%.2f days' % (seconds / 86400)
        if aname == 'lockoutduration' and (seconds is None or seconds == 0):
            return 'Until unlocked by an administrator'
        if seconds is None:
            return 'Never'
        return '%.1f minutes' % (seconds / 60)

    #Parse bitwise flags into a list
    def parseFlags(self, attr, flags_def):
        outflags = []
        if attr is None or attr.value is None:
            return outflags
        try:
            value = int(attr.value)
        except (TypeError, ValueError):
            return outflags
        for flag, val in flags_def.items():
            if value & val:
                outflags.append(flag)
        return outflags

    #Parse bitwise trust direction - only one flag applies here, 0x03 overlaps
    def parseSingleFlag(self, attr, flags_def):
        outflags = []
        if attr is None:
            return outflags
        for flag, val in flags_def.items():
            if int(attr.value) == val:
                outflags.append(flag)
        return outflags

    #Read a static file shipped with the package
    def readPackageFile(self, name):
        try:
            with codecs.open(os.path.join(os.path.dirname(__file__), name), 'r', 'utf8') as sf:
                return sf.read()
        except IOError:
            log_warn('%s not found in package directory, it will be skipped' % name)
            return ''

    #Domain name (DNS form) derived from the naming context
    def getDomainName(self):
        if self.dd is None or not getattr(self.dd, 'root', None):
            return ''
        try:
            return '.'.join(value for attr, value, _ in dn.parse_dn(self.dd.root) if attr.upper() == 'DC')
        except LDAPInvalidDnError:
            return self.dd.root

    #Name of the account behind a SID, when known
    def sidName(self, sid):
        return self.extra.get('sidmap', {}).get(sid, sid)

    #Convert a CN to a valid HTML id by replacing all non-ascii characters with a _
    def formatId(self, cn):
        return re.sub(r'[^a-zA-Z0-9_\-]+', '_', cn)

    #Link to another report (another file, or a section of the single HTML file)
    def pageLink(self, page, anchor=''):
        if self.config.singlefile:
            return '#' + (anchor or page)
        return '%s.html%s' % (page, ('#' + anchor) if anchor else '')

    # ------------------------------------------------------------------
    # Value formatting
    # ------------------------------------------------------------------

    #Dates AD uses for "never" (0 -> 1601, max int64 -> year 9999)
    def isNeverDate(self, value):
        return isinstance(value, datetime) and value.year in (1601, 9999)

    #Format a value for HTML
    def formatString(self, value):
        if isinstance(value, datetime):
            if self.isNeverDate(value):
                return 'Never'
            try:
                return value.strftime('%x %X')
            except ValueError:
                #Invalid date
                return '0'
        # Make sure it's a unicode string
        if type(value) is bytes:
            return value.decode('utf8', errors='replace')
        if type(value) is str:
            return value
        if value is None:
            return ''
        #Other type: convert it to a string
        return str(value)

    #ISO formatted date, sortable and locale independent
    def formatIsoDate(self, value):
        if self.isNeverDate(value):
            return 'Never'
        try:
            return value.strftime('%Y-%m-%d %H:%M:%S')
        except ValueError:
            return '0'

    #Render a list of flags as HTML badges
    def formatFlagsHtml(self, flags):
        return ''.join('<span class="badge%s">%s</span>' % (flag_severity.get(f, ''), self.htmlescape(f)) for f in flags)

    #Render a DN as its CN, with the full DN as tooltip
    def formatDnHtml(self, dnstr):
        return '<span class="item" title="%s">%s</span>' % (self.htmlescape(dnstr), self.htmlescape(rdn_value(dnstr)))

    #Names of the principals in a binary security descriptor attribute
    def sdPrincipals(self, att):
        try:
            raw = att.raw_values[0] if att.raw_values else None
        except (IndexError, AttributeError):
            raw = None
        return [self.sidName(sid) for sid in parse_sd_sids(raw)]

    #Format an attribute to a human readable format
    def formatAttribute(self, att, formatCnAsGroup=False):
        aname = att.key.lower()
        #User flags
        if aname == 'useraccountcontrol':
            return self.formatFlagsHtml(self.parseFlags(att, uac_flags))
        #List of groups
        if aname == 'member' or aname == 'memberof' and type(att.values) is list:
            return self.formatGroupsHtml(att.values)
        if aname in ('serviceprincipalname', 'msds-allowedtodelegateto') and type(att.values) is list:
            return self.formatSPNsHtml(att.values)
        #Primary group
        if aname == 'primarygroupid':
            try:
                return self.formatGroupsHtml([self.dd.groups_dnmap[att.value]])
            except KeyError:
                return 'NOT FOUND!'
        if aname == 'description' and type(att.values) is list:
            return self.htmlescape(" ".join(self.formatString(v) for v in att.values))
        if aname in ('manager', 'managedby') and att.value:
            return self.formatDnHtml(att.value)
        if aname == 'msds-supportedencryptiontypes':
            return self.formatFlagsHtml(self.parseFlags(att, ENCTYPE_FLAGS))
        if aname == 'msds-allowedtoactonbehalfofotheridentity':
            return ''.join('<span class="item">%s</span>' % self.htmlescape(p) for p in self.sdPrincipals(att))
        #Pwd flags
        if aname == 'pwdproperties':
            return self.formatFlagsHtml(self.parseFlags(att, pwd_flags))
        #Domain trust flags
        if aname == 'trustattributes':
            return self.formatFlagsHtml(self.parseFlags(att, trust_flags))
        if aname == 'trustdirection':
            if  att.value == 0:
                return self.formatFlagsHtml(['DISABLED'])
            else:
                return self.formatFlagsHtml(self.parseSingleFlag(att, trust_directions))
        if aname == 'trusttype':
            return self.formatFlagsHtml(self.parseSingleFlag(att, trust_type))
        if aname == 'securityidentifier':
            return self.htmlescape(format_sid(att.raw_values[0]))
        if aname in ('minpwdage', 'maxpwdage', 'lockoutobservationwindow', 'lockoutduration'):
            return self.htmlescape(self.formatPolicyInterval(aname, att.value))
        if aname == 'objectsid':
            return '<abbr class="sid" title="%s">%s</abbr>' % (self.htmlescape(att.value), self.htmlescape(att.value.split('-')[-1]))
        #Special case where the attribute is a CN and it should be made clear its a group
        if aname == 'cn' and formatCnAsGroup:
            return self.formatCnWithGroupLink(att.value)
        if isinstance(att.value, datetime):
            return self.formatIsoDate(att.value)
        #Other
        return self.htmlescape(self.formatString(att.value))

    def formatCnWithGroupLink(self, cn):
        return '<span class="badge tag">group</span> <a href="#cn_%s" title="%s">%s</a>' % (self.formatId(cn), self.htmlescape(cn), self.htmlescape(cn))

    # Fallback function for dirty DN parsing in case ldap3 functions error out
    def parseDnFallback(self, dn):
        try:
            indcn = dn[3:].index(',CN=')
            indou = dn[3:].index(',OU=')
            if indcn < indou:
                cn = dn[3:].split(',CN=')[0]
            else:
                cn = dn[3:].split(',OU=')[0]
        except ValueError:
            cn = dn
        return cn

    #CN of a group DN
    def groupCn(self, group):
        try:
            return self.unescapecn(dn.parse_dn(group)[0][1])
        except LDAPInvalidDnError:
            # Parsing failed, do it manually
            return self.unescapecn(self.parseDnFallback(group))

    #Format groups to readable HTML
    def formatGroupsHtml(self, grouplist):
        outcache = []
        for group in grouplist:
            cn = self.groupCn(group)
            outcache.append('<a href="%s" title="%s">%s</a>' % (self.pageLink(self.config.users_by_group, 'cn_' + self.formatId(cn)), self.htmlescape(group), self.htmlescape(cn)))
        return ', '.join(outcache)

    #Format groups to greppable format
    def formatGroupsGrep(self, grouplist):
        return ', '.join(self.groupCn(group) for group in grouplist)

    #Format SPNs to readable HTML
    def formatSPNsHtml(self, spnlist):
        return ''.join('<span class="spn">%s</span>' % self.htmlescape(spn) for spn in spnlist)

    #Format SPNs to greppable format
    def formatSPNsGrep(self, spnlist):
        return ','.join(spnlist)

    #Format attribute for grepping
    def formatGrepAttribute(self, att):
        aname = att.key.lower()
        #User flags
        if aname == 'useraccountcontrol':
            return ', '.join(self.parseFlags(att, uac_flags))
        #List of groups
        if aname == 'member' or aname == 'memberof' and type(att.values) is list:
            return self.formatGroupsGrep(att.values)
        if aname in ('serviceprincipalname', 'msds-allowedtodelegateto') and type(att.values) is list:
            return self.formatSPNsGrep(att.values)
        if aname == 'primarygroupid':
            try:
                return self.formatGroupsGrep([self.dd.groups_dnmap[att.value]])
            except KeyError:
                return 'NOT FOUND!'
        if aname == 'description' and type(att.values) is list:
            return " ".join(self.formatString(v) for v in att.values)
        if aname in ('manager', 'managedby') and att.value:
            return rdn_value(att.value)
        if aname == 'msds-supportedencryptiontypes':
            return ', '.join(self.parseFlags(att, ENCTYPE_FLAGS))
        if aname == 'msds-allowedtoactonbehalfofotheridentity':
            return ', '.join(self.sdPrincipals(att))
        #Domain trust flags
        if aname == 'trustattributes':
            return ', '.join(self.parseFlags(att, trust_flags))
        if aname == 'trustdirection':
            if att.value == 0:
                return 'DISABLED'
            else:
                return ', '.join(self.parseSingleFlag(att, trust_directions))
        if aname == 'trusttype':
            return ', '.join(self.parseSingleFlag(att, trust_type))
        if aname == 'securityidentifier':
            return format_sid(att.raw_values[0])
        #Pwd flags
        if aname == 'pwdproperties':
            return ', '.join(self.parseFlags(att, pwd_flags))
        if aname in ('minpwdage', 'maxpwdage', 'lockoutobservationwindow', 'lockoutduration'):
            return self.formatPolicyInterval(aname, att.value)
        return self.formatString(att.value)

    #Plain value (from the collected dict rows) to text
    def textValue(self, value):
        if isinstance(value, (list, tuple)):
            return ', '.join(self.textValue(v) for v in value)
        if isinstance(value, datetime):
            return self.formatIsoDate(value)
        if isinstance(value, bool):
            return 'Yes' if value else 'No'
        return self.formatString(value)

    #Plain value (from the collected dict rows) to an HTML cell
    def htmlCell(self, value):
        if isinstance(value, (list, tuple)):
            return '<td>%s</td>' % ''.join('<span class="item">%s</span>' % self.htmlescape(self.textValue(v)) for v in value)
        if isinstance(value, datetime):
            return '<td data-sort="%s">%s</td>' % (self.htmlescape(self.formatIsoDate(value)), self.htmlescape(self.formatIsoDate(value)))
        return '<td>%s</td>' % self.htmlescape(self.textValue(value))

    #JSON serialization of the collected dict rows
    def jsonDefault(self, value):
        if isinstance(value, datetime):
            return self.formatIsoDate(value)
        if isinstance(value, set):
            return sorted(value)
        if isinstance(value, bytes):
            return base64.b64encode(value).decode('ascii')
        return str(value)

    def dumpJson(self, data):
        return json.dumps(data, default=self.jsonDefault, ensure_ascii=False)

    # ------------------------------------------------------------------
    # HTML tables
    # ------------------------------------------------------------------

    #Generate a HTML table from a list of entries, with the specified attributes as column
    #In grouped mode, every group is a separate <tbody> of the same table, so that
    #the columns of all groups stay aligned
    def generateHtmlTable(self, listable, attributes, header='', firstTable=True, specialGroupsFormat=False, grouped=False, idprefix='cn_'):
        of = []
        if firstTable:
            of.append('<table class="report%s">' % (' grouped' if grouped else ''))
        headrow = []
        for hdr in attributes:
            #Print alias of this attribute if there is one
            hidden = ' data-hidden="1"' if hdr in HTML_HIDDEN_COLUMNS else ''
            headrow.append('<th scope="col"%s>%s</th>' % (hidden, self.htmlescape(attr_translations.get(hdr, hdr))))
        if grouped:
            of.append('<tbody class="grp" id="%s%s">' % (idprefix, self.formatId(header)))
            of.append('<tr class="grp-title"><td colspan="%d">%s<span class="count grp-count">%d</span></td></tr>' % (len(attributes), self.htmlescape(header), len(listable)))
            of.append('<tr class="hdr">%s</tr>\n' % ''.join(headrow))
        else:
            of.append('<thead><tr>%s</tr></thead>\n<tbody>' % ''.join(headrow))
        for li in listable:
            classes = ['row']
            #Whether we should format group objects separately
            liIsGroup = False
            try:
                if specialGroupsFormat and 'group' in li['objectClass'].values:
                    #Give it an extra class and pass it to the function below to make sure the CN is a link
                    liIsGroup = True
                    classes.append('group')
            except (LDAPKeyError, LDAPCursorError):
                pass
            try:
                if li['userAccountControl'].value is not None and int(li['userAccountControl'].value) & uac_flags['ACCOUNT_DISABLED']:
                    classes.append('disabled')
            except (LDAPKeyError, LDAPCursorError, ValueError, TypeError):
                pass
            of.append('<tr class="%s">' % ' '.join(classes))
            for att in attributes:
                try:
                    of.append(self.formatHtmlCell(li[att], liIsGroup))
                except (LDAPKeyError, LDAPCursorError):
                    of.append('<td></td>')
            of.append('</tr>\n')
        of.append('</tbody>\n')
        return ''.join(of)

    #Format a table cell, adding a sort key for values whose display is not naturally sortable
    def formatHtmlCell(self, att, formatCnAsGroup=False):
        sortkey = None
        if isinstance(att.value, datetime):
            sortkey = self.formatIsoDate(att.value) if not self.isNeverDate(att.value) else '0000'
        elif isinstance(att.value, timedelta):
            seconds = self.intervalToSeconds(att.value)
            sortkey = '%d' % (seconds if seconds is not None else 10**15)
        if sortkey is not None:
            return '<td data-sort="%s">%s</td>' % (self.htmlescape(sortkey), self.formatAttribute(att, formatCnAsGroup))
        return '<td>%s</td>' % self.formatAttribute(att, formatCnAsGroup)

    #Table of ldap3 entries in a card
    def entryTableHtml(self, entries, attributes):
        yield '<div class="card">'
        yield self.generateHtmlTable(entries, attributes)
        yield '</table></div>'

    #Grouped tables of ldap3 entries (users by group, computers by OS)
    def groupedEntryTablesHtml(self, groups, attributes, idprefix='cn_'):
        yield '<div class="card">'
        first = True
        for groupname in sorted(groups.keys(), key=lambda g: str(g).lower()):
            yield self.generateHtmlTable(groups[groupname], attributes, groupname, first, specialGroupsFormat=True, grouped=True, idprefix=idprefix)
            first = False
        if first:
            yield '<div class="empty">No entries</div>'
        else:
            yield '</table>'
        yield '</div>'

    #Generate a vertical key/value table (used for the domain policy which has a single entry)
    def keyValueEntryHtml(self, listable, attributes):
        yield '<div class="card"><table class="report kv">'
        for li in listable:
            yield '<tbody>'
            for att in attributes:
                yield '<tr class="row"><th scope="row">%s</th>' % self.htmlescape(attr_translations.get(att, att))
                try:
                    yield self.formatHtmlCell(li[att])
                except (LDAPKeyError, LDAPCursorError):
                    yield '<td></td>'
                yield '</tr>\n'
            yield '</tbody>\n'
        yield '</table></div>'

    #Table of collected dict rows. columns: list of (key, label) or (key, label, html formatter)
    def dictTableHtml(self, rows, columns, title=None, rowclass=None):
        yield '<div class="card">'
        if title:
            yield '<div class="card-head"><h2>%s</h2><span class="count">%d</span></div>' % (self.htmlescape(title), len(rows))
        yield '<table class="report"><thead><tr>%s</tr></thead><tbody>' % ''.join('<th scope="col">%s</th>' % self.htmlescape(c[1]) for c in columns)
        for row in rows:
            yield '<tr class="row%s">' % ((' ' + rowclass(row)) if rowclass and rowclass(row) else '')
            for col in columns:
                value = row.get(col[0])
                if len(col) > 2 and col[2] is not None:
                    yield '<td>%s</td>' % col[2](value, row)
                else:
                    yield self.htmlCell(value)
            yield '</tr>\n'
        yield '</tbody></table></div>'

    #Grouped tables of dict rows (groups: name -> rows)
    def groupedDictTablesHtml(self, groups, columns, idprefix):
        yield '<div class="card"><table class="report grouped">'
        headrow = ''.join('<th scope="col">%s</th>' % self.htmlescape(c[1]) for c in columns)
        for name, rows in groups.items():
            yield '<tbody class="grp" id="%s%s">' % (idprefix, self.formatId(name))
            yield '<tr class="grp-title"><td colspan="%d">%s<span class="count grp-count">%d</span></td></tr>' % (len(columns), self.htmlescape(name), len(rows))
            yield '<tr class="hdr">%s</tr>\n' % headrow
            for row in rows:
                yield '<tr class="row">'
                for col in columns:
                    value = row.get(col[0])
                    if len(col) > 2 and col[2] is not None:
                        yield '<td>%s</td>' % col[2](value, row)
                    else:
                        yield self.htmlCell(value)
                yield '</tr>\n'
            yield '</tbody>\n'
        yield '</table>'
        if not groups:
            yield '<div class="empty">No entries</div>'
        yield '</div>'

    #Key/value table of dict rows
    def kvDictHtml(self, rows, title=None):
        yield '<div class="card">'
        if title:
            yield '<div class="card-head"><h2>%s</h2></div>' % self.htmlescape(title)
        yield '<table class="report kv"><tbody>'
        for row in rows:
            yield '<tr class="row"><th scope="row">%s</th>%s</tr>\n' % (self.htmlescape(row['property']), self.htmlCell(row['value']))
        yield '</tbody></table></div>'

    # ------------------------------------------------------------------
    # Greppable / JSON
    # ------------------------------------------------------------------

    #Generate grep/awk/cut-able output
    def generateGrepList(self, entrylist, attributes):
        hdr = self.config.grepsplitchar.join(attributes)
        out = [hdr]
        for entry in entrylist:
            eo = []
            for attr in attributes:
                try:
                    eo.append(self.formatGrepAttribute(entry[attr]) or '')
                except (LDAPKeyError, LDAPCursorError):
                    eo.append('')
            out.append(self.config.grepsplitchar.join(eo))
        return '\n'.join(out)

    #Greppable output of dict rows
    def dictGrep(self, rows, keys, prefix=None):
        sep = self.config.grepsplitchar
        out = [sep.join(([prefix[0]] if prefix else []) + keys)]
        for row in rows:
            cells = [self.textValue(row.get(k)).replace(sep, ' ').replace('\n', ' ') for k in keys]
            out.append(sep.join(([prefix[1]] if prefix else []) + cells))
        return '\n'.join(out)

    #Greppable output of several named tables
    def sectionsGrep(self, sections):
        out = []
        for title, rows, keys in sections:
            out.append('# %s' % title)
            out.append(self.dictGrep(rows, keys))
            out.append('')
        return '\n'.join(out)

    #Convert a list of entities to a JSON string
    #String concatenation is used here since the entities have their own json generate
    #method and converting the string back to json just to process it would be inefficient
    def generateJsonList(self, entrylist):
        out = '[' + ','.join([entry.entry_to_json() for entry in entrylist]) + ']'
        return out

    #Convert a group key/value pair to json
    #Same methods as previous function are used
    def generateJsonGroup(self, group):
        out = '{%s:%s}' % (json.dumps(group[0]), self.generateJsonList(group[1]))
        return out

    #Convert a list of group dicts with entry lists to JSON string
    #Same methods as previous functions are used, except that text is returned
    #from a generator rather than allocating everything in memory
    def generateJsonGroupedList(self, groups):
        #Start of the list
        yield '['
        firstGroup = True
        for group in groups.items():
            if not firstGroup:
                #Separate items
                yield ','
            else:
                firstGroup = False
            yield self.generateJsonGroup(group)
        yield ']'

    # ------------------------------------------------------------------
    # Report definitions
    # ------------------------------------------------------------------

    def buildReports(self, dd):
        cnf = self.config
        ex = self.extra
        reports = []
        add = reports.append
        grouped_users = dd.sortUsersByGroup(dd.users)
        grouped_os = dd.sortComputersByOS(dd.computers)

        add(Report(cnf.indexfile, 'Overview', 'Overview', html=lambda: self.indexHtml(dd, grouped_os),
                   searchable=False, csv=False))

        #Domain information
        dc_cols = [('name', 'Name'), ('dNSHostName', 'DNS Hostname'), ('IPv4', 'IPv4 Address'), ('operatingSystem', 'Operating System'),
                   ('operatingSystemVersion', 'OS Version'), ('site', 'Site'), ('globalCatalog', 'Global catalog'), ('readOnly', 'Read-only')]
        fsmo_cols = [('role', 'Role'), ('scope', 'Scope'), ('holder', 'Holder'), ('site', 'Site')]
        site_cols = [('site', 'Site'), ('description', 'Description'), ('location', 'Location'), ('subnets', 'Subnets'), ('servers', 'Domain controllers'), ('whenCreated', 'Created on')]
        subnet_cols = [('subnet', 'Subnet'), ('site', 'Site'), ('location', 'Location'), ('description', 'Description')]
        link_cols = [('link', 'Site link'), ('transport', 'Transport'), ('sites', 'Sites'), ('cost', 'Cost'), ('replInterval', 'Replication interval (min)'), ('description', 'Description')]

        def domain_html():
            yield from self.kvDictHtml(ex.get('info', []), 'Domain')
            yield from self.dictTableHtml(ex.get('dcs', []), dc_cols, 'Domain controllers', rowclass=lambda r: 'disabled' if r.get('disabled') else '')
            yield from self.dictTableHtml(ex.get('fsmo', []), fsmo_cols, 'FSMO roles')
            yield from self.dictTableHtml(ex.get('sites', []), site_cols, 'Sites')
            yield from self.dictTableHtml(ex.get('subnets', []), subnet_cols, 'Subnets')
            yield from self.dictTableHtml(ex.get('sitelinks', []), link_cols, 'Site links')

        def domain_data():
            return {'info': {r['property']: r['value'] for r in ex.get('info', [])}, 'domainControllers': ex.get('dcs', []),
                    'fsmo': ex.get('fsmo', []), 'sites': ex.get('sites', []), 'subnets': ex.get('subnets', []),
                    'siteLinks': ex.get('sitelinks', [])}

        add(Report(cnf.domainfile, 'Domain information', 'Domain', html=domain_html,
                   json=lambda: [self.dumpJson(domain_data())],
                   grep=lambda: [self.sectionsGrep([('domain', ex.get('info', []), ['property', 'value']),
                                                    ('domain controllers', ex.get('dcs', []), [c[0] for c in dc_cols]),
                                                    ('fsmo roles', ex.get('fsmo', []), [c[0] for c in fsmo_cols]),
                                                    ('sites', ex.get('sites', []), [c[0] for c in site_cols]),
                                                    ('subnets', ex.get('subnets', []), [c[0] for c in subnet_cols]),
                                                    ('site links', ex.get('sitelinks', []), [c[0] for c in link_cols])])]))

        #Main objects
        add(Report(cnf.usersfile, 'Domain users', 'Users',
                   html=lambda: self.entryTableHtml(dd.users, self.userattributes),
                   json=lambda: [self.generateJsonList(dd.users)],
                   grep=lambda: [self.generateGrepList(dd.users, self.userattributes)],
                   hasDisabled=True, columns=True))
        add(Report(cnf.groupsfile, 'Domain groups', 'Groups',
                   html=lambda: self.entryTableHtml(dd.groups, self.groupattributes),
                   json=lambda: [self.generateJsonList(dd.groups)],
                   grep=lambda: [self.generateGrepList(dd.groups, self.groupattributes)],
                   columns=True))
        add(Report(cnf.computersfile, 'Domain computer accounts', 'Computers',
                   html=lambda: self.entryTableHtml(dd.computers, self.computerattributes),
                   json=lambda: [self.generateJsonList(dd.computers)],
                   grep=lambda: [self.generateGrepList(dd.computers, self.computerattributes)],
                   hasDisabled=True, columns=True))
        add(Report(cnf.policyfile, 'Domain policy', 'Policy',
                   html=lambda: self.keyValueEntryHtml(dd.policy, self.policyattributes),
                   json=lambda: [self.generateJsonList(dd.policy)],
                   grep=lambda: [self.generateGrepList(dd.policy, self.policyattributes)],
                   searchable=False))
        add(Report(cnf.trustsfile, 'Domain trusts', 'Trusts',
                   html=lambda: self.entryTableHtml(dd.trusts, self.trustattributes),
                   json=lambda: [self.generateJsonList(dd.trusts)],
                   grep=lambda: [self.generateGrepList(dd.trusts, self.trustattributes)]))

        #OUs and GPOs
        ou_cols = [('name', 'Name'), ('distinguishedName', 'Distinguished name'), ('description', 'Description'), ('linkedGPOs', 'Linked GPOs'),
                   ('blockInheritance', 'Block inheritance'), ('users', 'Users'), ('computers', 'Computers'), ('groups', 'Groups'), ('whenCreated', 'Created on')]
        add(Report(cnf.ousfile, 'Organizational units', 'OUs', html=self.ouTreeHtml,
                   json=lambda: [self.dumpJson(ex.get('ous', []))],
                   grep=lambda: [self.dictGrep(ex.get('ous', []), [c[0] for c in ou_cols])],
                   tree=True, csv=False))
        gpo_cols = [('name', 'Name'), ('status', 'Status'), ('linkedTo', 'Linked to'), ('wmiFilter', 'WMI filter'), ('guid', 'GUID'),
                    ('userVersion', 'User version'), ('computerVersion', 'Computer version'), ('path', 'SYSVOL path'),
                    ('whenCreated', 'Created on'), ('whenChanged', 'Changed on')]
        add(Report(cnf.gposfile, 'Group policy objects', 'GPOs',
                   html=lambda: self.dictTableHtml(ex.get('gpos', []), gpo_cols),
                   json=lambda: [self.dumpJson(ex.get('gpos', []))],
                   grep=lambda: [self.dictGrep(ex.get('gpos', []), [c[0] for c in gpo_cols])]))

        #DNS
        dns_cols = [('name', 'Name'), ('type', 'Type'), ('value', 'Value'), ('ttl', 'TTL'), ('timestamp', 'Timestamp')]
        zone_cols = [('zone', 'Zone'), ('partition', 'Partition'), ('records', 'Records')]

        def dns_grep():
            sep = self.config.grepsplitchar
            out = [sep.join(['zone'] + [c[0] for c in dns_cols])]
            for zone, rows in ex.get('dns', {}).items():
                out.extend(self.dictGrep(rows, [c[0] for c in dns_cols], prefix=('zone', zone)).split('\n')[1:])
            return ['\n'.join(out)]

        def dns_html():
            yield from self.dictTableHtml(ex.get('dns_zones', []), zone_cols, 'Zones')
            yield from self.groupedDictTablesHtml(ex.get('dns', {}), dns_cols, 'zone_')

        add(Report(cnf.dnsfile, 'DNS records', 'DNS', html=dns_html,
                   json=lambda: [self.dumpJson({'zones': ex.get('dns_zones', []), 'records': ex.get('dns', {})})],
                   grep=dns_grep, grouped=True))

        #PKI
        ca_cols = [('name', 'Name'), ('dNSHostName', 'DNS Hostname'), ('subject', 'Certificate subject'), ('notAfter', 'Valid until'),
                   ('templates', 'Published templates'), ('whenCreated', 'Created on')]
        root_cols = [('name', 'Name'), ('subject', 'Subject'), ('issuer', 'Issuer'), ('notBefore', 'Valid from'), ('notAfter', 'Valid until'), ('serial', 'Serial')]
        tpl_cols = [('name', 'Name'), ('displayName', 'Display name'), ('publishedBy', 'Published by'), ('schemaVersion', 'Schema version'),
                    ('extendedKeyUsage', 'Extended key usage'), ('nameFlags', 'Certificate name flags', self.flagListHtml),
                    ('enrollmentFlags', 'Enrollment flags', self.flagListHtml), ('raSignatures', 'RA signatures'),
                    ('validity', 'Validity'), ('whenChanged', 'Changed on')]

        def pki_html():
            yield from self.dictTableHtml(ex.get('cas', []), ca_cols, 'Enterprise certificate authorities')
            yield from self.dictTableHtml(ex.get('rootcas', []), root_cols, 'Root certificate authorities')
            yield from self.dictTableHtml(ex.get('templates', []), tpl_cols, 'Certificate templates',
                                          rowclass=lambda r: '' if r.get('publishedBy') else 'disabled')

        add(Report(cnf.pkifile, 'Public key infrastructure', 'PKI', html=pki_html,
                   json=lambda: [self.dumpJson({'certificateAuthorities': ex.get('cas', []), 'rootCertificateAuthorities': ex.get('rootcas', []),
                                                'templates': ex.get('templates', [])})],
                   grep=lambda: [self.sectionsGrep([('enterprise certificate authorities', ex.get('cas', []), [c[0] for c in ca_cols]),
                                                    ('root certificate authorities', ex.get('rootcas', []), [c[0] for c in root_cols]),
                                                    ('certificate templates', ex.get('templates', []), [c[0] for c in tpl_cols])])]))

        #Service accounts and SPNs
        msa_cols = [('name', 'SAM Name'), ('type', 'Type'), ('dNSHostName', 'DNS Hostname'), ('servicePrincipalName', 'SPN'),
                    ('principalsAllowedToRetrievePassword', 'Allowed to retrieve password'), ('hosts', 'Hosts'),
                    ('passwordInterval', 'Password interval (days)'), ('description', 'Description'), ('whenCreated', 'Created on')]
        spn_cols = [('account', 'Account'), ('type', 'Type'), ('host', 'Host'), ('spn', 'SPN')]

        def services_html():
            yield from self.dictTableHtml(ex.get('msas', []), msa_cols, 'Managed service accounts', rowclass=lambda r: 'disabled' if r.get('disabled') else '')
            yield from self.groupedDictTablesHtml(ex.get('spns', {}), spn_cols, 'svc_')

        def services_grep():
            sep = self.config.grepsplitchar
            out = ['# managed service accounts', self.dictGrep(ex.get('msas', []), [c[0] for c in msa_cols]), '', '# service principal names',
                   sep.join(['service'] + [c[0] for c in spn_cols])]
            for svc, rows in ex.get('spns', {}).items():
                out.extend(self.dictGrep(rows, [c[0] for c in spn_cols], prefix=('service', svc)).split('\n')[1:])
            return ['\n'.join(out)]

        add(Report(cnf.servicesfile, 'Service accounts and SPNs', 'Services', html=services_html,
                   json=lambda: [self.dumpJson({'managedServiceAccounts': ex.get('msas', []), 'servicePrincipalNames': ex.get('spns', {})})],
                   grep=services_grep, grouped=True, hasDisabled=True))

        #Contacts
        contact_cols = [('name', 'Name'), ('displayName', 'Display name'), ('mail', 'Mail'), ('description', 'Description'), ('memberOf', 'Member of groups'), ('whenCreated', 'Created on')]
        add(Report(cnf.contactsfile, 'Contacts', 'Contacts',
                   html=lambda: self.dictTableHtml(ex.get('contacts', []), contact_cols),
                   json=lambda: [self.dumpJson(ex.get('contacts', []))],
                   grep=lambda: [self.dictGrep(ex.get('contacts', []), [c[0] for c in contact_cols])]))

        #Foreign security principals
        fsp_cols = [('sid', 'SID'), ('name', 'Name'), ('memberOf', 'Member of groups'), ('whenCreated', 'Created on')]
        add(Report(cnf.foreignfile, 'Foreign security principals', 'Foreign principals',
                   html=lambda: self.dictTableHtml(ex.get('fsps', []), fsp_cols),
                   json=lambda: [self.dumpJson(ex.get('fsps', []))],
                   grep=lambda: [self.dictGrep(ex.get('fsps', []), [c[0] for c in fsp_cols])]))

        #Grouped views
        add(Report(cnf.users_by_group, 'Users by group', 'Users by group',
                   html=lambda: self.groupedEntryTablesHtml(grouped_users, self.userattributes_grouped),
                   json=(lambda: self.generateJsonGroupedList(grouped_users)) if cnf.groupedjson else None,
                   grouped=True, hasDisabled=True, columns=True))
        add(Report(cnf.computers_by_os, 'Computers by OS', 'Computers by OS',
                   html=lambda: self.groupedEntryTablesHtml(grouped_os, self.computerattributes, idprefix='os_'),
                   json=(lambda: self.generateJsonGroupedList(grouped_os)) if cnf.groupedjson else None,
                   grouped=True, hasDisabled=True, columns=True))
        add(Report(cnf.orgchartfile, 'Organization chart', 'Org chart', html=lambda: self.orgChartHtml(dd),
                   tree=True, csv=False))
        add(Report(cnf.membershipfile, 'Group memberships', 'Memberships', html=lambda: self.membershipHtml(dd),
                   searchable=False, csv=False))
        return reports

    #Flags rendered as badges, for dict rows
    def flagListHtml(self, value, row):
        return self.formatFlagsHtml(value or [])

    # ------------------------------------------------------------------
    # Special pages
    # ------------------------------------------------------------------

    def indexHtml(self, dd, grouped_os):
        ex = self.extra
        def enabled(entries):
            count = 0
            for e in entries:
                try:
                    if not int(e['userAccountControl'].value or 0) & uac_flags['ACCOUNT_DISABLED']:
                        count += 1
                except (LDAPKeyError, LDAPCursorError, ValueError, TypeError):
                    count += 1
            return count
        tiles = [('Users', len(dd.users), '%d enabled' % enabled(dd.users), self.config.usersfile),
                 ('Computers', len(dd.computers), '%d enabled' % enabled(dd.computers), self.config.computersfile),
                 ('Groups', len(dd.groups), '', self.config.groupsfile),
                 ('Domain controllers', len(ex.get('dcs', [])), '', self.config.domainfile),
                 ('OUs', max(len(ex.get('ous', [])) - 1, 0), '', self.config.ousfile),
                 ('GPOs', len(ex.get('gpos', [])), '', self.config.gposfile),
                 ('DNS records', sum(len(r) for r in ex.get('dns', {}).values()), '%d zones' % len(ex.get('dns_zones', [])), self.config.dnsfile),
                 ('Trusts', len(dd.trusts), '', self.config.trustsfile),
                 ('Certificate templates', len(ex.get('templates', [])), '%d CAs' % len(ex.get('cas', [])), self.config.pkifile),
                 ('Service accounts', len(ex.get('msas', [])), '%d SPN types' % len(ex.get('spns', {})), self.config.servicesfile),
                 ('Contacts', len(ex.get('contacts', [])), '', self.config.contactsfile),
                 ('Foreign principals', len(ex.get('fsps', [])), '', self.config.foreignfile)]
        yield '<div class="tiles">'
        for label, value, sub, page in tiles:
            yield '<a class="tile" href="%s"><span class="tile-value">%d</span><span class="tile-label">%s</span><span class="tile-sub">%s</span></a>' % (
                self.pageLink(page), value, self.htmlescape(label), self.htmlescape(sub))
        yield '</div>'
        yield '<div class="cols2">'
        yield from self.kvDictHtml(ex.get('info', []), 'Domain')
        osrows = sorted(((name, len(items)) for name, items in grouped_os.items()), key=lambda x: -x[1])
        total = max(sum(c for _, c in osrows), 1)
        yield '<div class="card"><div class="card-head"><h2>Operating systems</h2></div><div class="bars">'
        for name, count in osrows[:15]:
            yield '<a class="bar" href="%s"><span class="bar-label">%s</span><span class="bar-track"><span class="bar-fill" style="width:%.1f%%"></span></span><span class="bar-value">%d</span></a>' % (
                self.pageLink(self.config.computers_by_os, 'os_' + self.formatId(name)), self.htmlescape(name), 100.0 * count / total, count)
        if len(osrows) > 15:
            yield '<div class="bar-more">+ %d other operating systems</div>' % (len(osrows) - 15)
        yield '</div></div></div>'

    #Nested tree markup shared by the OU tree and the organization chart
    def treeHtml(self, roots, children, label, open_depth=1):
        out = ['<ul class="tree">']
        def render(key, depth, seen):
            kids = [k for k in children(key) if k not in seen]
            if kids:
                out.append('<li><details%s><summary>%s</summary><ul>' % (' open' if depth < open_depth else '', label(key)))
                for kid in kids:
                    render(kid, depth + 1, seen | {kid})
                out.append('</ul></details></li>')
            else:
                out.append('<li><span class="leaf">%s</span></li>' % label(key))
        for key in roots:
            render(key, 0, {key})
        out.append('</ul>')
        return ''.join(out)

    def ouTreeHtml(self):
        nodes = self.extra.get('ou_nodes')
        if not nodes:
            yield '<div class="card"><div class="empty">No entries</div></div>'
            return
        rootkey = self.extra['ou_root']
        icons = {'domain': '&#127760;', 'ou': '&#128193;', 'container': '&#128194;'}
        def label(key):
            n = nodes[key]
            parts = ['<span class="node" title="%s">%s %s</span>' % (self.htmlescape(n['dn']), icons.get(n['type'], ''), self.htmlescape(n['name']))]
            for kind in ('users', 'computers', 'groups', 'contacts'):
                if n['counts'].get(kind):
                    parts.append('<span class="badge tag">%d %s</span>' % (n['counts'][kind], kind))
            for name, opt in n.get('linkNames', []):
                parts.append('<span class="badge gpo" title="GPO link%s">GPO: %s%s</span>' % (
                    (' (%s)' % opt) if opt else '', self.htmlescape(name), (' (%s)' % self.htmlescape(opt)) if opt else ''))
            if n['blockInheritance']:
                parts.append('<span class="badge warn">block inheritance</span>')
            if n['description']:
                parts.append('<span class="node-desc">%s</span>' % self.htmlescape(n['description']))
            return ' '.join(parts)
        yield '<div class="card tree-card">'
        yield self.treeHtml([rootkey], lambda k: nodes[k]['children'], label, open_depth=2)
        yield '</div>'

    def orgChartHtml(self, dd):
        people = {}
        for user in dd.users:
            people[dn_key(user.entry_dn)] = user
        reports = {}
        for key, user in people.items():
            try:
                manager = user['manager'].value
            except (LDAPKeyError, LDAPCursorError, LDAPAttributeError):
                manager = None
            if manager and dn_key(manager) in people:
                reports.setdefault(dn_key(manager), []).append(key)
        def name(key):
            try:
                return people[key]['cn'].value or ''
            except (LDAPKeyError, LDAPCursorError):
                return ''
        for kids in reports.values():
            kids.sort(key=lambda k: name(k).lower())
        managed = set(k for kids in reports.values() for k in kids)
        roots = sorted((k for k in reports if k not in managed), key=lambda k: name(k).lower())
        def label(key):
            user = people[key]
            parts = ['<span class="node" title="%s">%s</span>' % (self.htmlescape(user.entry_dn), self.htmlescape(name(key)))]
            for attr in ('title', 'department'):
                try:
                    value = user[attr].value
                except (LDAPKeyError, LDAPCursorError, LDAPAttributeError):
                    value = None
                if value:
                    parts.append('<span class="badge tag">%s</span>' % self.htmlescape(str(value)))
            if key in reports:
                parts.append('<span class="node-desc">%d direct report%s</span>' % (len(reports[key]), 's' if len(reports[key]) > 1 else ''))
            return ' '.join(parts)
        yield '<div class="card tree-card">'
        if roots:
            yield self.treeHtml(roots, lambda k: reports.get(k, []), label, open_depth=2)
        else:
            yield '<div class="empty">No manager relationship found (the manager attribute is empty)</div>'
        yield '</div>'

    #Membership explorer: the group graph is embedded as JSON and explored client side
    def membershipHtml(self, dd):
        index = {}
        nodes = []
        def add(entry, kind):
            key = dn_key(entry.entry_dn)
            if key in index:
                return
            try:
                name = entry['sAMAccountName'].value or entry['cn'].value
            except (LDAPKeyError, LDAPCursorError):
                name = rdn_value(entry.entry_dn)
            index[key] = len(nodes)
            nodes.append([name, kind, entry.entry_dn, []])
        for group in dd.groups:
            add(group, 'g')
        for user in dd.users:
            add(user, 'u')
        for computer in dd.computers:
            add(computer, 'c')
        for entries in (dd.groups, dd.users, dd.computers):
            for entry in entries:
                node = nodes[index[dn_key(entry.entry_dn)]]
                try:
                    parents = list(entry['memberOf'].values)
                except (LDAPKeyError, LDAPCursorError):
                    parents = []
                try:
                    primary = self.dd.groups_dnmap.get(entry['primaryGroupId'].value)
                    if primary:
                        parents.append(primary)
                except (LDAPKeyError, LDAPCursorError):
                    pass
                for parent in parents:
                    pidx = index.get(dn_key(parent))
                    if pidx is not None and pidx not in node[3]:
                        node[3].append(pidx)
        data = json.dumps({'nodes': nodes}, ensure_ascii=False).replace('</', '<\\/')
        yield '<div class="card explorer"><div class="explorer-search"><input class="search explorer-input" type="search" '
        yield 'placeholder="Search a user, group or computer&hellip;" autocomplete="off"><ul class="explorer-results"></ul></div>'
        yield '<div class="explorer-view"><div class="empty">Select an object to see its memberships</div></div></div>'
        yield '<script type="application/json" class="membership-data">%s</script>' % data

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def ensureDir(self):
        if not os.path.exists(self.config.basepath):
            os.makedirs(self.config.basepath)

    #Page toolbar
    def htmlToolbar(self, r):
        out = ['<div class="toolbar"><h1>%s</h1>' % self.htmlescape(r.title)]
        if r.searchable:
            out.append('<span class="count row-count"></span>')
        out.append('<span class="spacer"></span>')
        if r.grouped or r.tree:
            out.append('<button class="icon-btn expand-all" type="button">Expand all</button>')
            out.append('<button class="icon-btn collapse-all" type="button">Collapse all</button>')
        if r.hasDisabled:
            out.append('<label><input type="checkbox" class="hide-disabled"> Hide disabled</label>')
        if r.columns:
            out.append('<details class="colmenu"><summary class="icon-btn">Columns</summary><div class="colmenu-list"></div></details>')
        if r.csv:
            out.append('<button class="icon-btn csv-export" type="button" title="Export the visible rows to CSV">CSV</button>')
        if r.searchable:
            out.append('<input class="search filter" type="search" placeholder="Filter&hellip;  (press / to focus)" autocomplete="off">')
        out.append('<button class="icon-btn theme-toggle" type="button" title="Toggle dark mode">&#9680;</button>')
        out.append('</div>\n')
        return ''.join(out)

    #Page shell: head, sidebar navigation and the report sections
    def htmlShell(self, title, reports, active=None):
        domain = self.getDomainName()
        nav = []
        for r in reports:
            nav.append('<a href="%s" data-page="%s"%s>%s</a>' % (self.pageLink(r.name), r.name, ' class="active"' if r.name == active else '', self.htmlescape(r.label)))
        sub = ' &middot; '.join(x for x in [self.htmlescape(domain), self.generated] if x)
        head = ''.join(['<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta charset="UTF-8">\n',
                        '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
                        '<title>%s%s</title>\n' % (self.htmlescape(title), (' - %s' % self.htmlescape(domain)) if domain else ''),
                        '<style>%s</style>\n</head>\n<body%s>\n' % (self.css, ' class="single"' if self.config.singlefile else ''),
                        '<aside class="sidebar"><div class="brand"><div class="brand-logo">LDD</div><div>',
                        '<div class="brand-title">ldapdomaindump-ng</div><div class="brand-sub">%s</div></div></div>' % sub,
                        '<nav class="nav">%s</nav></aside>\n<main>\n' % ''.join(nav)])
        foot = '</main>\n<script>%s</script>\n</body>\n</html>\n' % self.js
        return head, foot

    #One report as an HTML section
    def htmlSection(self, r):
        yield '<section class="page" id="%s"%s%s>\n' % (r.name, ' data-columns="1"' if r.columns else '', ' hidden' if self.config.singlefile else '')
        yield self.htmlToolbar(r)
        yield '<div class="page-body">\n'
        for chunk in r.html():
            yield chunk
        yield '\n</div></section>\n'

    def writeChunks(self, rel_outfile, chunks):
        self.ensureDir()
        outfile = os.path.join(self.config.basepath, rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            for chunk in chunks:
                of.write(chunk)

    def writeHtml(self, reports):
        if self.config.singlefile:
            head, foot = self.htmlShell('Domain dump', reports)
            def chunks():
                yield head
                for r in reports:
                    yield from self.htmlSection(r)
                yield foot
            self.writeChunks('%s.html' % self.config.singlefilename, chunks())
            return
        for r in reports:
            head, foot = self.htmlShell(r.title, reports, active=r.name)
            def chunks(r=r, head=head, foot=foot):
                yield head
                yield from self.htmlSection(r)
                yield foot
            self.writeChunks('%s.html' % r.name, chunks())

    def writeJson(self, reports):
        reports = [r for r in reports if r.json]
        if self.config.singlefile:
            def chunks():
                yield '{'
                for i, r in enumerate(reports):
                    yield '%s%s:' % (',' if i else '', json.dumps(r.name))
                    yield from r.json()
                yield '}'
            self.writeChunks('%s.json' % self.config.singlefilename, chunks())
            return
        for r in reports:
            self.writeChunks('%s.json' % r.name, r.json())

    def writeGrep(self, reports):
        reports = [r for r in reports if r.grep]
        if self.config.singlefile:
            def chunks():
                for r in reports:
                    yield '### %s (%s)\n' % (r.title, r.name)
                    yield from r.grep()
                    yield '\n\n'
            self.writeChunks('%s.grep' % self.config.singlefilename, chunks())
            return
        for r in reports:
            self.writeChunks('%s.grep' % r.name, r.grep())

    #Write all the reports in the selected formats
    def writeReports(self, dd):
        self.dd = dd
        self.extra = getattr(dd, 'extra', None) or {}
        dd.mapGroupsIdsToDns()
        reports = self.buildReports(dd)
        if self.config.outputhtml:
            self.writeHtml(reports)
        if self.config.outputjson:
            self.writeJson(reports)
        if self.config.outputgrep:
            self.writeGrep(reports)

#Some quick logging helpers
def log_warn(text):
    print('[!] %s' % text)
def log_info(text):
    print('[*] %s' % text)
def log_success(text):
    print('[+] %s' % text)

OUTPUT_FORMATS = ('html', 'json', 'grep')

#Parse the output formats given on the command line: "-f html,json" or "-f html -f json"
def parse_formats(values):
    formats = []
    for value in values:
        for fmt in re.split(r'[,\s]+', value.strip().lower()):
            if fmt == '':
                continue
            if fmt == 'all':
                formats.extend(OUTPUT_FORMATS)
            elif fmt in OUTPUT_FORMATS:
                formats.append(fmt)
            else:
                raise argparse.ArgumentTypeError('invalid output format "%s" (choose from: %s, all)' % (fmt, ', '.join(OUTPUT_FORMATS)))
    return set(formats)

#Split a down-level username (DOMAIN\username or DOMAIN/username) into (username, domain)
#The shell often doubles (or strips) the backslash, so any run of backslashes is accepted.
#UPN usernames (user@domain) and plain usernames are returned unchanged.
def split_downlevel_username(username):
    if username is None:
        return None, None
    username = re.sub(r'\\+', lambda m: '\\', username.strip())
    for sep in ('\\', '/'):
        if sep in username:
            domain, _, user = username.partition(sep)
            if domain and user:
                return user, domain
    return username, None

HELP_EPILOG = r"""examples:
  %(prog)s -u user@corp.local -p 'Passw0rd' dc01.corp.local
  %(prog)s -u 'CORP\user' -p 'Passw0rd' 10.0.0.10
  %(prog)s -u user@corp.local --hashes :<NThash> dc01.corp.local
  %(prog)s -u user@corp.local -k -no-pass dc01.corp.local     (KRB5CCNAME=user.ccache)
  %(prog)s -u user@corp.local -aesKey <hexkey> dc01.corp.local
  %(prog)s -u user@corp.local -p 'Passw0rd' --ldap-channel-binding ldaps://dc01.corp.local"""

def _build_parser():
    parser = argparse.ArgumentParser(description='ldapdomaindump-ng: Active Directory information dumper via LDAP. Dumps users, groups, computers,\nOUs, GPOs, DNS, PKI and more to HTML/JSON/greppable output.',
                                     formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=HELP_EPILOG)
    parser._optionals.title = "Main options"
    parser._positionals.title = "Required options"

    #Main parameters
    parser.add_argument("host", type=str, metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to (use ldaps:// to use SSL)")

    #Authentication parameters
    authgroup = parser.add_argument_group("Authentication options")
    authgroup.add_argument("-u", "--username", "--user", dest='username', type=str, metavar='USERNAME',
                           help="Username: user@domain (UPN), DOMAIN\\user or DOMAIN/user. Leave empty for anonymous bind")
    authgroup.add_argument("-p", "--password", type=str, metavar='PASSWORD',
                           help="Password for authentication. Prompted if not specified (unless -no-pass, -k, --hashes or -aesKey is used)")
    authgroup.add_argument("--domain", type=str, metavar='DOMAIN', default=None,
                           help="Domain/realm, used when the username does not contain one")
    authgroup.add_argument("--auth-method", dest='auth_method', choices=['auto', 'ntlm', 'kerberos'], default='auto',
                           help="Authentication method (default: auto, try Kerberos first and fall back to NTLM)")
    authgroup.add_argument("-k", "--kerberos", action='store_true', default=False,
                           help="Use Kerberos authentication with the ticket from the KRB5CCNAME ccache. Implies --auth-method kerberos")
    authgroup.add_argument("--hashes", type=str, metavar='LMHASH:NTHASH', default=None,
                           help="NTLM hashes in LM:NT format (LM can be blank: :NT). The NT hash is also usable as an RC4 key for Kerberos")
    authgroup.add_argument("-aesKey", dest='aesKey', type=str, metavar='HEXKEY', default=None,
                           help="AES128 (32 hex) or AES256 (64 hex) Kerberos key")
    authgroup.add_argument("-no-pass", dest='no_pass', action='store_true', default=False,
                           help="Don't prompt for a password (useful with -k, --hashes or -aesKey)")

    #Connection parameters
    conngroup = parser.add_argument_group("Connection options")
    conngroup.add_argument("--start-tls", action='store_true', default=False,
                           help="Upgrade plain LDAP to TLS with StartTLS before binding (not compatible with ldaps://)")
    conngroup.add_argument("--ldap-channel-binding", dest='ldap_channel_binding', action='store_true', default=False,
                           help="Use LDAP channel binding (EPA, RFC 5929 tls-server-end-point) over ldaps:// or StartTLS, for NTLM and Kerberos")
    conngroup.add_argument("--no-tls-verify", action='store_true', default=False,
                           help="Disable TLS certificate validation (insecure, for self-signed DC certificates)")

    #Output parameters
    outputgroup = parser.add_argument_group("Output options")
    outputgroup.add_argument("-o", "--outdir", type=str, metavar='DIRECTORY', help="Directory in which the dump will be saved (default: current)")
    outputgroup.add_argument("-f", "--format", action='append', metavar='FORMATS', help="Output formats to generate, comma separated or repeated: html, json, grep or all (default: all). Example: -f html,json")
    #Kept for backwards compatibility, -f/--format should be used instead
    outputgroup.add_argument("--no-html", action='store_true', help=argparse.SUPPRESS)
    outputgroup.add_argument("--no-json", action='store_true', help=argparse.SUPPRESS)
    outputgroup.add_argument("--no-grep", action='store_true', help=argparse.SUPPRESS)
    outputgroup.add_argument("--single-file", action='store_true', default=False, help="Write a single file per output format (domain_dump.html/.json/.grep) instead of one file per report")
    outputgroup.add_argument("--grouped-json", action='store_true', default=False, help="Also write json files for grouped files (default: disabled)")
    outputgroup.add_argument("-d", "--delimiter", help="Field delimiter for greppable output (default: tab)")

    #Additional options
    miscgroup = parser.add_argument_group("Misc options")
    miscgroup.add_argument("-r", "--resolve", action='store_true', help="Resolve computer hostnames (might take a while and cause high traffic on large networks)")
    miscgroup.add_argument("-n", "--dns-server", help="DNS server used to resolve the DC hostname and computer hostnames (try a domain controller IP)")
    miscgroup.add_argument("-m", "--minimal", action='store_true', default=False, help="Only query minimal set of attributes to limit memmory usage")
    miscgroup.add_argument("--debug", action='store_true', default=False,
                           help="Enable verbose debug logging (auth flow and ldap3 EXTENDED logs)")

    return parser


def _prompt_password_if_needed(args):
    """Prompt for a password if one is needed and not supplied."""
    if args.username is None:
        return
    if args.no_pass:
        return
    if args.kerberos:
        return
    if args.hashes or args.aesKey:
        return
    if args.password is None:
        args.password = getpass.getpass()


def _validate_args(parser, args):
    """Cross-field argparse validation that argparse groups can't express natively."""
    #Accept DOMAIN\user and DOMAIN/user by converting them to username + --domain
    user, domain = split_downlevel_username(args.username)
    if domain is not None:
        args.username = user
        if not args.domain:
            args.domain = domain
            args.domain_from_username = True
    if args.start_tls and args.host.lower().startswith('ldaps://'):
        parser.error('--start-tls is incompatible with ldaps:// (connection is already TLS)')
    if args.hashes is not None and not re.match(r'^[0-9a-fA-F]{0,32}:[0-9a-fA-F]{32}$', args.hashes):
        parser.error('--hashes must be in LM:NT format (32 hex each, LM may be blank)')
    if args.aesKey is not None and len(args.aesKey) not in (32, 64):
        parser.error('-aesKey must be 32 or 64 hex characters (AES128 or AES256)')
    if args.aesKey is not None:
        try:
            int(args.aesKey, 16)
        except ValueError:
            parser.error('-aesKey must be 32 or 64 hex characters (AES128 or AES256)')
    if args.kerberos and args.auth_method == 'ntlm':
        parser.error('-k requires Kerberos; cannot combine with --auth-method ntlm')
    if args.kerberos and args.username is None:
        parser.error('-k requires a username; anonymous Kerberos is not supported')
    if args.auth_method == 'kerberos' and args.username is None:
        parser.error('--auth-method kerberos requires a username; anonymous Kerberos is not supported')
    if args.kerberos and args.auth_method == 'auto':
        args.auth_method = 'kerberos'


def main():
    parser = _build_parser()
    args = parser.parse_args()
    _validate_args(parser, args)
    import logging
    if not args.debug:
        logging.basicConfig(level=logging.WARNING, format='[!] %(message)s', stream=sys.stdout)
    else:
        logging.basicConfig(level=logging.DEBUG,
                            format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
        try:
            from ldap3.utils.log import set_library_log_detail_level, EXTENDED
            set_library_log_detail_level(EXTENDED)
        except Exception:
            pass
    #Create default config
    cnf = domainDumpConfig()
    #Dns lookups?
    if args.resolve:
        cnf.lookuphostnames = True
    #Custom dns server?
    if args.dns_server is not None:
        cnf.dnsserver = args.dns_server
    #Minimal attributes?
    if args.minimal:
        cnf.minimal = True
    #Custom separator?
    if args.delimiter is not None:
        cnf.grepsplitchar = args.delimiter
    #Output formats
    if args.format:
        try:
            formats = parse_formats(args.format)
        except argparse.ArgumentTypeError as e:
            parser.error(str(e))
    else:
        formats = set(OUTPUT_FORMATS)
    if args.no_html:
        formats.discard('html')
    if args.no_json:
        formats.discard('json')
    if args.no_grep:
        formats.discard('grep')
    if not formats:
        parser.error('no output format selected')
    cnf.outputhtml = 'html' in formats
    cnf.outputjson = 'json' in formats
    cnf.outputgrep = 'grep' in formats
    log_info('Output formats: %s' % ', '.join(f for f in OUTPUT_FORMATS if f in formats))
    #Custom outdir?
    if args.outdir is not None:
        cnf.basepath = args.outdir
    #Do we really need grouped json files?
    cnf.groupedjson = args.grouped_json
    #One file per format?
    cnf.singlefile = args.single_file

    _prompt_password_if_needed(args)
    if args.username is None:
        log_info('Connecting as anonymous user, dumping will probably fail. Consider specifying a username/password to login with')

    log_info('Connecting to %s' % args.host)
    try:
        from ldapdomaindump.auth import build_connection, AuthError
        c = build_connection(args)
    except AuthError as e:
        log_warn(str(e))
        sys.exit(1)
    except LDAPSocketOpenError as e:
        log_warn('Could not connect to %s: %s' % (args.host, e))
        sys.exit(1)
    s = c.server
    log_success('Bind OK')
    log_info('Starting domain dump')
    #Create domaindumper object
    dd = domainDumper(s, c, cnf)

    #Do the actual dumping
    dd.domainDump()
    log_success('Domain dump finished')

if __name__ == '__main__':
    main()
