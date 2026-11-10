"""Additional collection for ldapdomaindump.

Domain/forest information, domain controllers, sites, OUs, GPOs, AD integrated
DNS, PKI, contacts, foreign security principals and managed service accounts.
Everything here is plain LDAP data readable by a standard domain user.
"""
import logging
import re
import socket
import struct
from datetime import datetime, timedelta, timezone

from ldap3 import BASE, LEVEL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPKeyError, LDAPCursorError, LDAPAttributeError, LDAPInvalidDnError
from ldap3.utils import dn as ldapdn

log = logging.getLogger(__name__)

# Schema objectVersion -> Windows version
SCHEMA_VERSIONS = {13: 'Windows 2000', 30: 'Windows Server 2003', 31: 'Windows Server 2003 R2',
                   44: 'Windows Server 2008', 47: 'Windows Server 2008 R2', 56: 'Windows Server 2012',
                   69: 'Windows Server 2012 R2', 87: 'Windows Server 2016', 88: 'Windows Server 2019/2022',
                   91: 'Windows Server 2025'}

# msDS-Behavior-Version -> functional level
FUNCTIONAL_LEVELS = {0: 'Windows 2000', 1: 'Windows Server 2003 interim', 2: 'Windows Server 2003',
                     3: 'Windows Server 2008', 4: 'Windows Server 2008 R2', 5: 'Windows Server 2012',
                     6: 'Windows Server 2012 R2', 7: 'Windows Server 2016', 10: 'Windows Server 2025'}

# msDS-SupportedEncryptionTypes flags
ENCTYPE_FLAGS = {'DES_CBC_CRC': 0x1, 'DES_CBC_MD5': 0x2, 'RC4_HMAC': 0x4,
                 'AES128_CTS_HMAC_SHA1_96': 0x8, 'AES256_CTS_HMAC_SHA1_96': 0x10,
                 'AES256_SK': 0x20, 'FAST_SUPPORTED': 0x10000, 'COMPOUND_IDENTITY_SUPPORTED': 0x20000,
                 'CLAIMS_SUPPORTED': 0x40000, 'RESOURCE_SID_COMPRESSION_DISABLED': 0x80000}

# groupPolicyContainer flags
GPO_STATUS = {0: 'Enabled', 1: 'User settings disabled', 2: 'Computer settings disabled', 3: 'All settings disabled'}

# gPLink options
GPLINK_OPTIONS = {0: '', 1: 'disabled', 2: 'enforced', 3: 'enforced, disabled'}

# msPKI-Certificate-Name-Flag (MS-CRTD 2.28)
PKI_NAME_FLAGS = {'ENROLLEE_SUPPLIES_SUBJECT': 0x00000001,
                  'OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME': 0x00000008,
                  'ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME': 0x00010000,
                  'SUBJECT_ALT_REQUIRE_DOMAIN_DNS': 0x00400000,
                  'SUBJECT_ALT_REQUIRE_SPN': 0x00800000,
                  'SUBJECT_ALT_REQUIRE_DIRECTORY_GUID': 0x01000000,
                  'SUBJECT_ALT_REQUIRE_UPN': 0x02000000,
                  'SUBJECT_ALT_REQUIRE_EMAIL': 0x04000000,
                  'SUBJECT_ALT_REQUIRE_DNS': 0x08000000,
                  'SUBJECT_REQUIRE_DNS_AS_CN': 0x10000000,
                  'SUBJECT_REQUIRE_EMAIL': 0x20000000,
                  'SUBJECT_REQUIRE_COMMON_NAME': 0x40000000,
                  'SUBJECT_REQUIRE_DIRECTORY_PATH': 0x80000000}

# msPKI-Enrollment-Flag (MS-CRTD 2.26)
PKI_ENROLLMENT_FLAGS = {'INCLUDE_SYMMETRIC_ALGORITHMS': 0x00000001,
                        'PEND_ALL_REQUESTS': 0x00000002,
                        'PUBLISH_TO_KRA_CONTAINER': 0x00000004,
                        'PUBLISH_TO_DS': 0x00000008,
                        'AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE': 0x00000010,
                        'AUTO_ENROLLMENT': 0x00000020,
                        'PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT': 0x00000040,
                        'USER_INTERACTION_REQUIRED': 0x00000100,
                        'REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE': 0x00000400,
                        'ALLOW_ENROLL_ON_BEHALF_OF': 0x00000800,
                        'ADD_OCSP_NOCHECK': 0x00001000,
                        'ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL': 0x00002000,
                        'NOREVOCATIONINFOINISSUEDCERTS': 0x00004000,
                        'INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS': 0x00008000,
                        'ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT': 0x00010000,
                        'ISSUANCE_POLICIES_FROM_REQUEST': 0x00020000,
                        'SKIP_AUTO_RENEWAL': 0x00040000,
                        'NO_SECURITY_EXTENSION': 0x00080000}

# Common Extended Key Usage OIDs
EKU_NAMES = {'1.3.6.1.5.5.7.3.1': 'Server Authentication',
             '1.3.6.1.5.5.7.3.2': 'Client Authentication',
             '1.3.6.1.5.5.7.3.3': 'Code Signing',
             '1.3.6.1.5.5.7.3.4': 'Secure Email',
             '1.3.6.1.5.5.7.3.8': 'Time Stamping',
             '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
             '1.3.6.1.5.2.3.4': 'PKINIT Client Authentication',
             '1.3.6.1.5.2.3.5': 'KDC Authentication',
             '1.3.6.1.4.1.311.20.2.1': 'Certificate Request Agent',
             '1.3.6.1.4.1.311.20.2.2': 'Smart Card Logon',
             '1.3.6.1.4.1.311.10.3.1': 'Microsoft Trust List Signing',
             '1.3.6.1.4.1.311.10.3.4': 'Encrypting File System',
             '1.3.6.1.4.1.311.10.3.4.1': 'File Recovery',
             '1.3.6.1.4.1.311.10.3.11': 'Key Recovery',
             '1.3.6.1.4.1.311.10.3.12': 'Document Signing',
             '1.3.6.1.4.1.311.10.3.13': 'Lifetime Signing',
             '1.3.6.1.4.1.311.21.5': 'Private Key Archival',
             '1.3.6.1.4.1.311.21.6': 'Key Recovery Agent',
             '1.3.6.1.4.1.311.21.19': 'Directory Service Email Replication',
             '1.3.6.1.4.1.311.54.1.2': 'Remote Desktop Authentication',
             '1.3.6.1.5.5.8.2.2': 'IP Security IKE Intermediate',
             '2.5.29.37.0': 'Any Purpose'}

# Well-known SIDs that show up as foreign security principals
WELL_KNOWN_SIDS = {'S-1-0-0': 'Nobody', 'S-1-1-0': 'Everyone', 'S-1-5-1': 'Dialup', 'S-1-5-2': 'Network',
                   'S-1-5-3': 'Batch', 'S-1-5-4': 'Interactive', 'S-1-5-6': 'Service', 'S-1-5-7': 'Anonymous Logon',
                   'S-1-5-9': 'Enterprise Domain Controllers', 'S-1-5-10': 'Self', 'S-1-5-11': 'Authenticated Users',
                   'S-1-5-13': 'Terminal Server Users', 'S-1-5-14': 'Remote Interactive Logon',
                   'S-1-5-15': 'This Organization', 'S-1-5-17': 'IUSR', 'S-1-5-18': 'Local System',
                   'S-1-5-19': 'Local Service', 'S-1-5-20': 'Network Service', 'S-1-5-1000': 'Other Organization',
                   'S-1-5-113': 'Local account', 'S-1-5-114': 'Local account and member of Administrators group'}

# DNS record types (MS-DNSP 2.2.2.1.1)
DNS_TYPES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 13: 'HINFO', 15: 'MX', 16: 'TXT',
             17: 'RP', 18: 'AFSDB', 24: 'SIG', 25: 'KEY', 28: 'AAAA', 33: 'SRV', 35: 'NAPTR', 39: 'DNAME',
             43: 'DS', 46: 'RRSIG', 47: 'NSEC', 48: 'DNSKEY', 50: 'NSEC3', 51: 'NSEC3PARAM', 52: 'TLSA',
             0xFF01: 'WINS', 0xFF02: 'WINSR', 0: 'ZERO'}

# userAccountControl flags used here
UAC_SERVER_TRUST_ACCOUNT = 0x00002000
UAC_PARTIAL_SECRETS_ACCOUNT = 0x04000000
UAC_ACCOUNTDISABLE = 0x00000002


def first(values, default=None):
    """First element of a list-ish value."""
    if values is None:
        return default
    if isinstance(values, (list, tuple)):
        return values[0] if values else default
    return values


def val(entry, attr, default=None):
    """Value of an entry attribute, or default when missing."""
    try:
        value = entry[attr].value
    except (LDAPKeyError, LDAPCursorError, LDAPAttributeError, KeyError, IndexError):
        return default
    return default if value is None else value


def vals(entry, attr):
    """All values of an entry attribute as a list."""
    try:
        values = entry[attr].values
    except (LDAPKeyError, LDAPCursorError, LDAPAttributeError, KeyError, IndexError):
        return []
    return list(values) if values is not None else []


def rawval(entry, attr):
    """First raw (bytes) value of an attribute."""
    try:
        raw = entry[attr].raw_values
    except (LDAPKeyError, LDAPCursorError, LDAPAttributeError, KeyError, IndexError):
        return None
    return raw[0] if raw else None


def entry_dn(entry):
    return entry.entry_dn


def rdn_value(dnstr, index=0):
    """Value of the RDN at a given index of a DN ('CN=a,OU=b' -> 'a' for index 0)."""
    if not dnstr:
        return ''
    try:
        parts = ldapdn.parse_dn(dnstr)
        value = parts[index][1]
    except (LDAPInvalidDnError, IndexError):
        pieces = split_dn(dnstr)
        if index >= len(pieces):
            return dnstr
        value = pieces[index].split('=', 1)[-1]
    return unescape_dn_value(value)


def unescape_dn_value(value):
    return re.sub(r'\\(.)', r'\1', value)


def split_dn(dnstr):
    """Split a DN on unescaped commas."""
    return [p for p in re.split(r'(?<!\\),', dnstr) if p]


def parent_dn(dnstr):
    parts = split_dn(dnstr)
    return ','.join(parts[1:])


def dn_key(dnstr):
    """Normalized DN for dictionary keys."""
    return ','.join(p.strip() for p in split_dn(dnstr or '')).lower()


def domain_from_dn(dnstr):
    """DC=corp,DC=local -> corp.local"""
    return '.'.join(p.split('=', 1)[1] for p in split_dn(dnstr) if p.upper().startswith('DC='))


def parse_flags(value, flags):
    if value is None:
        return []
    try:
        value = int(value)
    except (TypeError, ValueError):
        return []
    return [name for name, bit in flags.items() if value & bit]


def filetime_interval_days(raw):
    """pKIExpirationPeriod / pKIOverlapPeriod (8 bytes, negative 100ns intervals) to a readable string."""
    if not raw or len(raw) != 8:
        return ''
    seconds = -struct.unpack('<q', raw)[0] / 10000000
    days = seconds / 86400
    if days >= 365 and days % 365 == 0:
        years = int(days // 365)
        return '%d year%s' % (years, 's' if years > 1 else '')
    if days >= 7 and days % 7 == 0 and days < 365:
        weeks = int(days // 7)
        return '%d week%s' % (weeks, 's' if weeks > 1 else '')
    if days >= 1:
        return '%d day%s' % (int(days), 's' if int(days) > 1 else '')
    return '%d hours' % int(seconds // 3600)


def parse_sd_sids(raw):
    """Return the SIDs of the ACEs of a binary security descriptor (msDS-AllowedToActOnBehalfOfOtherIdentity,
    msDS-GroupMSAMembership)."""
    if not raw:
        return []
    try:
        from impacket.ldap import ldaptypes
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=raw)
        if not sd['Dacl']:
            return []
        return [ace['Ace']['Sid'].formatCanonical() for ace in sd['Dacl'].aces]
    except Exception as exc:
        log.debug('Could not parse security descriptor: %s', exc)
        return []


def parse_gplink(gplink):
    """Parse a gPLink value into a list of (GPO GUID, options)."""
    links = []
    if not gplink:
        return links
    for path, options in re.findall(r'\[LDAP://([^;\]]+);(\d+)\]', gplink, re.I):
        guid = re.search(r'\{[0-9A-Fa-f-]+\}', path)
        if guid:
            links.append((guid.group(0).upper(), int(options)))
    return links


def parse_certificate(raw):
    """Subject, issuer and validity of a DER certificate."""
    if not raw:
        return {}
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(raw)
        try:
            not_after = cert.not_valid_after_utc
            not_before = cert.not_valid_before_utc
        except AttributeError:
            not_after = cert.not_valid_after
            not_before = cert.not_valid_before
        return {'subject': cert.subject.rfc4514_string(), 'issuer': cert.issuer.rfc4514_string(),
                'notBefore': not_before, 'notAfter': not_after, 'serial': '%x' % cert.serial_number}
    except Exception as exc:
        log.debug('Could not parse certificate: %s', exc)
        return {}


# ---------------------------------------------------------------------------
# AD integrated DNS (MS-DNSP dnsRecord)
# ---------------------------------------------------------------------------

def _dns_count_name(data, offset=0):
    """DNS_COUNT_NAME: length, label count, then length-prefixed labels."""
    if len(data) < offset + 2:
        return '', offset
    length = data[offset]
    labels = data[offset + 1]
    pos = offset + 2
    parts = []
    for _ in range(labels):
        if pos >= len(data):
            break
        llen = data[pos]
        parts.append(data[pos + 1:pos + 1 + llen].decode('utf-8', errors='replace'))
        pos += 1 + llen
    return '.'.join(parts) + '.', offset + 2 + length


def _dns_name_string(data, offset=0):
    """DNS_RPC_NAME: length-prefixed string."""
    if len(data) <= offset:
        return '', offset
    length = data[offset]
    return data[offset + 1:offset + 1 + length].decode('utf-8', errors='replace'), offset + 1 + length


def parse_dns_record(raw):
    """Parse a dnsRecord attribute value. Returns a dict with type, value, ttl and timestamp."""
    if not raw or len(raw) < 24:
        return None
    data_length, rtype, _version, _rank, _flags, _serial = struct.unpack('<HHBBHI', raw[:12])
    ttl = struct.unpack('>I', raw[12:16])[0]
    timestamp = struct.unpack('<I', raw[20:24])[0]
    data = raw[24:24 + data_length]
    tname = DNS_TYPES.get(rtype, 'TYPE%d' % rtype)
    value = ''
    try:
        if rtype == 1 and len(data) >= 4:
            value = socket.inet_ntoa(data[:4])
        elif rtype == 28 and len(data) >= 16:
            value = socket.inet_ntop(socket.AF_INET6, data[:16])
        elif rtype in (2, 5, 12, 39):
            value = _dns_count_name(data)[0]
        elif rtype == 15:
            pref = struct.unpack('>H', data[:2])[0]
            value = '%d %s' % (pref, _dns_count_name(data, 2)[0])
        elif rtype == 33:
            priority, weight, port = struct.unpack('>HHH', data[:6])
            value = '%d %d %d %s' % (priority, weight, port, _dns_count_name(data, 6)[0])
        elif rtype == 6:
            serial, refresh, retry, expire, minimum = struct.unpack('>IIIII', data[:20])
            primary, pos = _dns_count_name(data, 20)
            admin = _dns_count_name(data, pos)[0]
            value = '%s %s %d %d %d %d %d' % (primary, admin, serial, refresh, retry, expire, minimum)
        elif rtype == 16:
            pos, texts = 0, []
            while pos < len(data):
                text, pos = _dns_name_string(data, pos)
                texts.append('"%s"' % text)
            value = ' '.join(texts)
        elif rtype == 0:
            value = '(tombstoned)'
        else:
            value = data.hex()
    except (struct.error, ValueError, OSError):
        value = data.hex()
    if timestamp == 0:
        ts = 'static'
    else:
        ts = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(hours=timestamp)
    return {'type': tname, 'value': value, 'ttl': ttl, 'timestamp': ts}


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class ExtraCollector(object):
    """Collects the additional information from a domainDumper connection."""

    def __init__(self, dd):
        self.dd = dd
        self.conn = dd.connection
        self.server = dd.server
        self.root = dd.root
        other = {}
        if self.server.info is not None and self.server.info.other:
            other = self.server.info.other
        self.config_nc = first(other.get('configurationNamingContext')) or 'CN=Configuration,%s' % self.root
        self.schema_nc = first(other.get('schemaNamingContext')) or 'CN=Schema,%s' % self.config_nc
        self.forest_root = first(other.get('rootDomainNamingContext')) or self.root
        self.dc_hostname = first(other.get('dnsHostName')) or ''
        self.data = {}

    # -- helpers -------------------------------------------------------------

    def attrs(self, names):
        """Keep only the attributes known by the server schema (ldap3 rejects unknown ones)."""
        schema = self.server.schema
        if schema is None:
            return names
        return [a for a in names if a in schema.attribute_types]

    def search(self, base, flt, attrs, scope=SUBTREE):
        try:
            if scope == BASE:
                self.conn.search(base, flt, search_scope=BASE, attributes=self.attrs(attrs))
            else:
                self.conn.extend.standard.paged_search(base, flt, search_scope=scope, attributes=self.attrs(attrs),
                                                       paged_size=500, generator=False)
            return list(self.conn.entries)
        except LDAPException as exc:
            log.debug('Search %s %s failed: %s', base, flt, exc)
            return []

    def base(self, base, attrs):
        entries = self.search(base, '(objectClass=*)', attrs, scope=BASE)
        return entries[0] if entries else None

    def step(self, name, func):
        try:
            func()
        except Exception as exc:
            log.warning('Could not collect %s: %s', name, exc)
            log.debug('Collection error', exc_info=True)

    # -- collection ----------------------------------------------------------

    def collect(self):
        self.build_sid_map()
        self.step('domain information', self.collect_domain)
        self.step('sites', self.collect_sites)
        self.step('domain controllers', self.collect_dcs)
        self.step('contacts', self.collect_contacts)
        self.step('GPOs', self.collect_gpos)
        self.step('OUs', self.collect_ous)
        self.step('DNS records', self.collect_dns)
        self.step('PKI', self.collect_pki)
        self.step('managed service accounts', self.collect_msas)
        self.step('SPNs', self.collect_spns)
        return self.data

    def build_sid_map(self):
        sidmap = dict(WELL_KNOWN_SIDS)
        for entries in (self.dd.users, self.dd.computers, self.dd.groups):
            for entry in entries or []:
                sid = val(entry, 'objectSid')
                if sid:
                    sidmap[str(sid)] = val(entry, 'sAMAccountName') or val(entry, 'cn') or str(sid)
        self.data['sidmap'] = sidmap

    def sid_name(self, sid):
        return self.data['sidmap'].get(sid, sid)

    def collect_domain(self):
        info = []
        add = lambda k, v: info.append({'property': k, 'value': v}) if v not in (None, '', []) else None
        dom = self.base(self.root, ['msDS-Behavior-Version', 'whenCreated', 'objectSid', 'fSMORoleOwner',
                                    'ms-DS-MachineAccountQuota', 'gPLink', 'gPOptions'])
        part = self.base('CN=Partitions,%s' % self.config_nc, ['msDS-Behavior-Version', 'fSMORoleOwner'])
        crossrefs = self.search('CN=Partitions,%s' % self.config_nc, '(objectClass=crossRef)',
                                ['nCName', 'dnsRoot', 'nETBIOSName', 'systemFlags', 'trustParent'], scope=LEVEL)
        schema = self.base(self.schema_nc, ['objectVersion', 'fSMORoleOwner'])
        rid = self.base('CN=RID Manager$,CN=System,%s' % self.root, ['fSMORoleOwner'])
        infra = self.base('CN=Infrastructure,%s' % self.root, ['fSMORoleOwner'])
        exch = self.base('CN=ms-Exch-Schema-Version-Pt,%s' % self.schema_nc, ['rangeUpper'])
        exorg = self.search('CN=Microsoft Exchange,CN=Services,%s' % self.config_nc,
                            '(objectClass=msExchOrganizationContainer)', ['name'], scope=LEVEL)
        recycle = self.base('CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,'
                            'CN=Services,%s' % self.config_nc, ['msDS-EnabledFeatureBL'])

        netbios = ''
        forest_domains = []
        for cr in crossrefs:
            ncname = val(cr, 'nCName') or ''
            flags = int(val(cr, 'systemFlags') or 0)
            if dn_key(ncname) == dn_key(self.root):
                netbios = val(cr, 'nETBIOSName') or ''
            if flags & 2:
                forest_domains.append(val(cr, 'dnsRoot') or domain_from_dn(ncname))

        add('Domain', domain_from_dn(self.root))
        add('NetBIOS name', netbios)
        add('Domain SID', str(val(dom, 'objectSid') or '') if dom else '')
        add('Distinguished name', self.root)
        if dom is not None and val(dom, 'msDS-Behavior-Version') is not None:
            level = int(val(dom, 'msDS-Behavior-Version'))
            add('Domain functional level', '%s (%d)' % (FUNCTIONAL_LEVELS.get(level, 'Unknown'), level))
        if part is not None and val(part, 'msDS-Behavior-Version') is not None:
            level = int(val(part, 'msDS-Behavior-Version'))
            add('Forest functional level', '%s (%d)' % (FUNCTIONAL_LEVELS.get(level, 'Unknown'), level))
        add('Forest root', domain_from_dn(self.forest_root))
        add('Forest domains', sorted(forest_domains))
        if schema is not None and val(schema, 'objectVersion') is not None:
            version = int(val(schema, 'objectVersion'))
            add('Schema version', '%s (%d)' % (SCHEMA_VERSIONS.get(version, 'Unknown'), version))
        if exch is not None and val(exch, 'rangeUpper') is not None:
            add('Exchange schema version', str(val(exch, 'rangeUpper')))
        add('Exchange organization', [val(e, 'name') for e in exorg])
        if recycle is not None:
            add('Recycle Bin', 'Enabled' if vals(recycle, 'msDS-EnabledFeatureBL') else 'Disabled')
        if dom is not None:
            add('Machine account quota', val(dom, 'ms-DS-MachineAccountQuota'))
            add('Created', val(dom, 'whenCreated'))
        add('Queried DC', self.dc_hostname)
        self.data['info'] = info
        self.data['domain_gplink'] = (val(dom, 'gPLink') or '', val(dom, 'gPOptions') or 0) if dom else ('', 0)

        fsmo = []
        for role, entry, scope in (('Schema master', schema, 'Forest'),
                                   ('Domain naming master', part, 'Forest'),
                                   ('PDC emulator', dom, 'Domain'),
                                   ('RID master', rid, 'Domain'),
                                   ('Infrastructure master', infra, 'Domain')):
            owner = val(entry, 'fSMORoleOwner') if entry is not None else None
            if owner:
                fsmo.append({'role': role, 'scope': scope, 'holder': rdn_value(owner, 1),
                             'site': rdn_value(owner, 3), 'distinguishedName': owner})
        self.data['fsmo'] = fsmo

    def collect_sites(self):
        sites_base = 'CN=Sites,%s' % self.config_nc
        sites = self.search(sites_base, '(objectClass=site)', ['name', 'description', 'location', 'whenCreated'],
                            scope=LEVEL)
        subnets = self.search('CN=Subnets,%s' % sites_base, '(objectClass=subnet)',
                              ['name', 'siteObject', 'location', 'description', 'whenCreated'], scope=LEVEL)
        links = self.search('CN=Inter-Site Transports,%s' % sites_base, '(objectClass=siteLink)',
                            ['name', 'siteList', 'cost', 'replInterval', 'options', 'description'])
        servers = self.search(sites_base, '(objectClass=server)', ['name', 'dNSHostName', 'serverReference'])
        ntds = self.search(sites_base, '(objectClass=nTDSDSA)', ['options'])

        site_subnets = {}
        rows = []
        for sn in subnets:
            site = rdn_value(val(sn, 'siteObject') or '')
            site_subnets.setdefault(site.lower(), []).append(val(sn, 'name'))
            rows.append({'subnet': val(sn, 'name'), 'site': site, 'location': val(sn, 'location', ''),
                         'description': ' '.join(vals(sn, 'description'))})
        self.data['subnets'] = sorted(rows, key=lambda r: r['subnet'] or '')

        self.data['servers'] = []
        for srv in servers:
            sdn = entry_dn(srv)
            gc = False
            for n in ntds:
                if dn_key(parent_dn(entry_dn(n))) == dn_key(sdn):
                    gc = bool(int(val(n, 'options') or 0) & 1)
            self.data['servers'].append({'name': val(srv, 'name'), 'dNSHostName': val(srv, 'dNSHostName', ''),
                                         'serverReference': val(srv, 'serverReference', ''),
                                         'site': rdn_value(sdn, 2), 'gc': gc})

        site_rows = []
        for site in sites:
            name = val(site, 'name')
            site_rows.append({'site': name, 'description': ' '.join(vals(site, 'description')),
                              'location': val(site, 'location', ''),
                              'subnets': sorted(site_subnets.get((name or '').lower(), [])),
                              'servers': sorted(s['name'] for s in self.data['servers']
                                                if (s['site'] or '').lower() == (name or '').lower()),
                              'whenCreated': val(site, 'whenCreated')})
        self.data['sites'] = sorted(site_rows, key=lambda r: (r['site'] or '').lower())

        link_rows = []
        for link in links:
            link_rows.append({'link': val(link, 'name'), 'transport': rdn_value(entry_dn(link), 1),
                              'sites': sorted(rdn_value(s) for s in vals(link, 'siteList')),
                              'cost': val(link, 'cost'), 'replInterval': val(link, 'replInterval'),
                              'description': ' '.join(vals(link, 'description'))})
        self.data['sitelinks'] = link_rows

    def collect_dcs(self):
        servers = self.data.get('servers', [])
        rows = []
        for comp in self.dd.computers or []:
            uac = int(val(comp, 'userAccountControl') or 0)
            if not uac & (UAC_SERVER_TRUST_ACCOUNT | UAC_PARTIAL_SECRETS_ACCOUNT):
                continue
            cdn = entry_dn(comp)
            host = val(comp, 'dNSHostName', '')
            server = next((s for s in servers if dn_key(s['serverReference']) == dn_key(cdn)
                           or (host and (s['dNSHostName'] or '').lower() == host.lower())), None)
            rows.append({'name': val(comp, 'cn'), 'dNSHostName': host,
                         'IPv4': val(comp, 'IPv4', ''),
                         'operatingSystem': val(comp, 'operatingSystem', ''),
                         'operatingSystemVersion': val(comp, 'operatingSystemVersion', ''),
                         'site': server['site'] if server else '',
                         'globalCatalog': 'Yes' if server and server['gc'] else 'No',
                         'readOnly': 'Yes' if uac & UAC_PARTIAL_SECRETS_ACCOUNT else 'No',
                         'disabled': bool(uac & UAC_ACCOUNTDISABLE),
                         'distinguishedName': cdn})
        self.data['dcs'] = sorted(rows, key=lambda r: (r['name'] or '').lower())

    def collect_gpos(self):
        gpos = self.search('CN=Policies,CN=System,%s' % self.root, '(objectClass=groupPolicyContainer)',
                           ['displayName', 'name', 'gPCFileSysPath', 'flags', 'versionNumber', 'whenCreated',
                            'whenChanged', 'gPCWQLFilter', 'distinguishedName'], scope=LEVEL)
        wmi = self.search('CN=SOM,CN=WMIPolicy,CN=System,%s' % self.root, '(objectClass=msWMI-Som)',
                          ['msWMI-Name', 'msWMI-ID'], scope=LEVEL)
        wmi_names = {(val(w, 'msWMI-ID') or '').upper(): val(w, 'msWMI-Name') for w in wmi}
        rows = []
        for gpo in gpos:
            version = int(val(gpo, 'versionNumber') or 0)
            wql = val(gpo, 'gPCWQLFilter') or ''
            wql_guid = re.search(r'\{[0-9A-Fa-f-]+\}', wql)
            rows.append({'name': val(gpo, 'displayName') or val(gpo, 'name'),
                         'guid': (val(gpo, 'name') or '').upper(),
                         'status': GPO_STATUS.get(int(val(gpo, 'flags') or 0), str(val(gpo, 'flags'))),
                         'linkedTo': [],
                         'wmiFilter': wmi_names.get(wql_guid.group(0).upper(), wql) if wql_guid else '',
                         'userVersion': version >> 16, 'computerVersion': version & 0xFFFF,
                         'path': val(gpo, 'gPCFileSysPath', ''),
                         'whenCreated': val(gpo, 'whenCreated'), 'whenChanged': val(gpo, 'whenChanged')})
        self.data['gpos'] = sorted(rows, key=lambda r: (r['name'] or '').lower())

    def collect_ous(self):
        ous = self.search(self.root, '(objectClass=organizationalUnit)',
                          ['name', 'description', 'gPLink', 'gPOptions', 'whenCreated', 'distinguishedName'])
        gpo_by_guid = {g['guid']: g for g in self.data.get('gpos', [])}

        nodes = {}

        def node(dnstr, kind=None):
            key = dn_key(dnstr)
            if key not in nodes:
                first_rdn = split_dn(dnstr)[0] if dnstr else ''
                if kind is None:
                    kind = 'ou' if first_rdn.upper().startswith('OU=') else 'container'
                nodes[key] = {'dn': dnstr, 'name': rdn_value(dnstr), 'type': kind, 'description': '',
                              'links': [], 'blockInheritance': False, 'counts': {}, 'children': set()}
            return nodes[key]

        rootnode = node(self.root, 'domain')
        rootnode['name'] = domain_from_dn(self.root)
        gplink, gpoptions = self.data.get('domain_gplink', ('', 0))
        rootnode['links'] = parse_gplink(gplink)
        rootnode['blockInheritance'] = int(gpoptions or 0) == 1

        rows = []
        for ou in ous:
            n = node(entry_dn(ou), 'ou')
            n['description'] = ' '.join(vals(ou, 'description'))
            n['links'] = parse_gplink(val(ou, 'gPLink'))
            n['blockInheritance'] = int(val(ou, 'gPOptions') or 0) == 1
            n['whenCreated'] = val(ou, 'whenCreated')

        # Count objects per container, creating the containers that hold them
        for kind, entries in (('users', self.dd.users), ('computers', self.dd.computers),
                              ('groups', self.dd.groups), ('contacts', self.data.get('contact_entries', []))):
            for entry in entries or []:
                container = node(parent_dn(entry_dn(entry)))
                container['counts'][kind] = container['counts'].get(kind, 0) + 1

        # Link every node to its parent up to the domain root
        rootkey = dn_key(self.root)
        for key in list(nodes.keys()):
            current = nodes[key]
            while dn_key(current['dn']) != rootkey and current['dn']:
                pdn = parent_dn(current['dn'])
                if not pdn or len(split_dn(pdn)) < len(split_dn(self.root)):
                    break
                parent = node(pdn)
                parent['children'].add(dn_key(current['dn']))
                current = parent

        for n in nodes.values():
            n['children'] = sorted(n['children'], key=lambda k: (nodes[k]['type'] != 'ou', nodes[k]['name'].lower()))
            n['linkNames'] = [(gpo_by_guid[g]['name'] if g in gpo_by_guid else g, GPLINK_OPTIONS.get(o, str(o)))
                              for g, o in n['links']]
            if n['type'] in ('ou', 'domain'):
                rows.append({'name': n['name'], 'distinguishedName': n['dn'], 'description': n['description'],
                             'linkedGPOs': ['%s (%s)' % (name, opt) if opt else name for name, opt in n['linkNames']],
                             'blockInheritance': 'Yes' if n['blockInheritance'] else 'No',
                             'users': n['counts'].get('users', 0), 'computers': n['counts'].get('computers', 0),
                             'groups': n['counts'].get('groups', 0), 'whenCreated': n.get('whenCreated')})
            # GPO -> containers it is linked to
            for guid, opt in n['links']:
                if guid in gpo_by_guid:
                    label = n['dn'] if n['type'] != 'domain' else n['name']
                    option = GPLINK_OPTIONS.get(opt, str(opt))
                    gpo_by_guid[guid]['linkedTo'].append('%s (%s)' % (label, option) if option else label)

        self.data['ou_nodes'] = nodes
        self.data['ou_root'] = rootkey
        self.data['ous'] = sorted(rows, key=lambda r: [p.lower() for p in reversed(split_dn(r['distinguishedName']))])

    def collect_dns(self):
        bases = ['CN=MicrosoftDNS,DC=DomainDnsZones,%s' % self.root,
                 'CN=MicrosoftDNS,DC=ForestDnsZones,%s' % self.forest_root,
                 'CN=MicrosoftDNS,CN=System,%s' % self.root]
        zones = []
        seen = set()
        for base in bases:
            for zone in self.search(base, '(objectClass=dnsZone)', ['name', 'whenCreated'], scope=LEVEL):
                name = val(zone, 'name') or ''
                if name in ('RootDNSServers', '..TrustAnchors') or name.lower() in seen:
                    continue
                seen.add(name.lower())
                partition = 'DomainDnsZones' if 'DomainDnsZones' in base else (
                    'ForestDnsZones' if 'ForestDnsZones' in base else 'Legacy (System)')
                zones.append((name, partition, entry_dn(zone)))

        records = {}
        zone_rows = []
        for name, partition, zdn in zones:
            rows = []
            for nd in self.search(zdn, '(objectClass=dnsNode)', ['name', 'dnsRecord', 'dNSTombstoned'], scope=LEVEL):
                if val(nd, 'dNSTombstoned') is True:
                    continue
                rname = val(nd, 'name') or ''
                fqdn = name if rname == '@' else '%s.%s' % (rname, name)
                try:
                    raws = nd['dnsRecord'].raw_values
                except (LDAPKeyError, LDAPCursorError, LDAPAttributeError, KeyError):
                    raws = []
                if not raws:
                    rows.append({'name': fqdn, 'type': '?', 'value': '(not readable)', 'ttl': '', 'timestamp': ''})
                    continue
                for raw in raws:
                    rec = parse_dns_record(raw)
                    if rec is None or rec['type'] == 'ZERO':
                        continue
                    rows.append(dict(name=fqdn, **rec))
            rows.sort(key=lambda r: (r['name'].lower(), r['type']))
            records[name] = rows
            zone_rows.append({'zone': name, 'partition': partition, 'records': len(rows)})
        self.data['dns'] = records
        self.data['dns_zones'] = zone_rows

    def collect_pki(self):
        pki = 'CN=Public Key Services,CN=Services,%s' % self.config_nc
        cas = self.search('CN=Enrollment Services,%s' % pki, '(objectClass=pKIEnrollmentService)',
                          ['name', 'dNSHostName', 'cACertificate', 'certificateTemplates', 'whenCreated'], scope=LEVEL)
        roots = self.search('CN=Certification Authorities,%s' % pki, '(objectClass=certificationAuthority)',
                            ['name', 'cACertificate', 'whenCreated'], scope=LEVEL)
        templates = self.search('CN=Certificate Templates,%s' % pki, '(objectClass=pKICertificateTemplate)',
                                ['name', 'displayName', 'msPKI-Template-Schema-Version', 'pKIExtendedKeyUsage',
                                 'msPKI-Certificate-Application-Policy', 'msPKI-Certificate-Name-Flag',
                                 'msPKI-Enrollment-Flag', 'msPKI-RA-Signature', 'pKIExpirationPeriod',
                                 'msPKI-Cert-Template-OID', 'whenChanged'], scope=LEVEL)
        published = {}
        ca_rows = []
        for ca in cas:
            cert = parse_certificate(rawval(ca, 'cACertificate'))
            name = val(ca, 'name')
            for tpl in vals(ca, 'certificateTemplates'):
                published.setdefault(tpl.lower(), []).append(name)
            ca_rows.append({'name': name, 'dNSHostName': val(ca, 'dNSHostName', ''),
                            'subject': cert.get('subject', ''), 'notAfter': cert.get('notAfter'),
                            'templates': sorted(vals(ca, 'certificateTemplates'), key=str.lower),
                            'whenCreated': val(ca, 'whenCreated')})
        self.data['cas'] = ca_rows
        root_rows = []
        for root in roots:
            for raw in (root['cACertificate'].raw_values if 'cACertificate' in root else []):
                cert = parse_certificate(raw)
                root_rows.append({'name': val(root, 'name'), 'subject': cert.get('subject', ''),
                                  'issuer': cert.get('issuer', ''), 'notBefore': cert.get('notBefore'),
                                  'notAfter': cert.get('notAfter'), 'serial': cert.get('serial', '')})
        self.data['rootcas'] = root_rows
        tpl_rows = []
        for tpl in templates:
            name = val(tpl, 'name') or ''
            ekus = vals(tpl, 'pKIExtendedKeyUsage') or vals(tpl, 'msPKI-Certificate-Application-Policy')
            tpl_rows.append({'name': name, 'displayName': val(tpl, 'displayName', ''),
                             'schemaVersion': val(tpl, 'msPKI-Template-Schema-Version'),
                             'publishedBy': sorted(published.get(name.lower(), [])),
                             'extendedKeyUsage': [EKU_NAMES.get(o, o) for o in ekus],
                             'nameFlags': parse_flags(val(tpl, 'msPKI-Certificate-Name-Flag'), PKI_NAME_FLAGS),
                             'enrollmentFlags': parse_flags(val(tpl, 'msPKI-Enrollment-Flag'), PKI_ENROLLMENT_FLAGS),
                             'raSignatures': val(tpl, 'msPKI-RA-Signature', 0),
                             'validity': filetime_interval_days(rawval(tpl, 'pKIExpirationPeriod')),
                             'whenChanged': val(tpl, 'whenChanged')})
        self.data['templates'] = sorted(tpl_rows, key=lambda r: (not r['publishedBy'], r['name'].lower()))

    def collect_contacts(self):
        contacts = self.search(self.root, '(objectClass=contact)',
                               ['cn', 'displayName', 'mail', 'description', 'memberOf', 'whenCreated',
                                'distinguishedName'])
        self.data['contact_entries'] = contacts
        self.data['contacts'] = [{'name': val(c, 'cn'), 'displayName': val(c, 'displayName', ''),
                                  'mail': val(c, 'mail', ''), 'description': ' '.join(vals(c, 'description')),
                                  'memberOf': [rdn_value(g) for g in vals(c, 'memberOf')],
                                  'whenCreated': val(c, 'whenCreated'), 'distinguishedName': entry_dn(c)}
                                 for c in contacts]
        fsps = self.search('CN=ForeignSecurityPrincipals,%s' % self.root, '(objectClass=foreignSecurityPrincipal)',
                           ['cn', 'memberOf', 'whenCreated'], scope=LEVEL)
        self.data['fsps'] = [{'sid': val(f, 'cn'), 'name': WELL_KNOWN_SIDS.get(val(f, 'cn'), ''),
                              'memberOf': [rdn_value(g) for g in vals(f, 'memberOf')],
                              'whenCreated': val(f, 'whenCreated')} for f in fsps]

    def collect_msas(self):
        msas = self.search(self.root, '(|(objectClass=msDS-GroupManagedServiceAccount)'
                                      '(objectClass=msDS-ManagedServiceAccount))',
                           ['sAMAccountName', 'objectClass', 'dNSHostName', 'servicePrincipalName',
                            'msDS-ManagedPasswordInterval', 'msDS-GroupMSAMembership', 'msDS-HostServiceAccountBL',
                            'description', 'whenCreated', 'userAccountControl'])
        rows = []
        for m in msas:
            classes = [c.lower() for c in vals(m, 'objectClass')]
            gmsa = 'msds-groupmanagedserviceaccount' in classes
            readers = [self.sid_name(s) for s in parse_sd_sids(rawval(m, 'msDS-GroupMSAMembership'))]
            rows.append({'name': val(m, 'sAMAccountName'), 'type': 'gMSA' if gmsa else 'sMSA',
                         'dNSHostName': val(m, 'dNSHostName', ''),
                         'servicePrincipalName': vals(m, 'servicePrincipalName'),
                         'passwordInterval': val(m, 'msDS-ManagedPasswordInterval', ''),
                         'principalsAllowedToRetrievePassword': readers,
                         'hosts': [rdn_value(h) for h in vals(m, 'msDS-HostServiceAccountBL')],
                         'description': ' '.join(vals(m, 'description')),
                         'disabled': bool(int(val(m, 'userAccountControl') or 0) & UAC_ACCOUNTDISABLE),
                         'whenCreated': val(m, 'whenCreated')})
        self.data['msas'] = sorted(rows, key=lambda r: (r['name'] or '').lower())

    def collect_spns(self):
        services = {}
        for kind, entries in (('user', self.dd.users), ('computer', self.dd.computers)):
            for entry in entries or []:
                for spn in vals(entry, 'servicePrincipalName'):
                    cls, _, target = spn.partition('/')
                    services.setdefault(cls, []).append({'account': val(entry, 'sAMAccountName'), 'type': kind,
                                                         'host': target, 'spn': spn})
        for rows in services.values():
            rows.sort(key=lambda r: ((r['account'] or '').lower(), r['spn'].lower()))
        self.data['spns'] = dict(sorted(services.items(), key=lambda kv: kv[0].lower()))
