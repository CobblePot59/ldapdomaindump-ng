"""Authentication dispatcher for ldapdomaindump.

Parses argparse output into an ADAuthentication instance and returns a bound
ldap3.Connection via `build_connection(args)`.
"""
import re
import ssl
import sys

from ldap3 import ALL, Server, Tls

from ldapdomaindump.authentication import ADAuthentication


class AuthError(RuntimeError):
    """Raised when authentication cannot be completed."""


_IP_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')


def _build_server(args):
    """Build an ldap3.Server with TLS settings derived from args.host."""
    validate = ssl.CERT_NONE if getattr(args, 'no_tls_verify', False) else ssl.CERT_REQUIRED
    if validate == ssl.CERT_NONE:
        print(
            '[!] TLS certificate validation disabled. '
            'Connection is encrypted but not authenticated.',
            file=sys.stderr,
        )
    # When connecting to a resolved IP, still validate the certificate against the DC hostname
    tls = Tls(validate=validate, valid_names=getattr(args, 'tls_names', None))
    use_ssl = args.host.lower().startswith('ldaps://')
    return Server(args.host, get_info=ALL, use_ssl=use_ssl, tls=tls)


def _resolve(hostname, dns_server):
    """Resolve hostname to an IPv4 address with a specific DNS server."""
    import dns.resolver
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server]
    resolver.lifetime = 3
    try:
        return str(resolver.resolve(hostname, 'A')[0])
    except Exception as exc:
        raise AuthError('could not resolve %s via %s (%s)' % (hostname, dns_server, type(exc).__name__))


def _replace_hostname(host, hostname, ip):
    """Swap the hostname in an ldap[s]://host:port string for an IP."""
    scheme, sep, rest = host.rpartition('://')
    return scheme + sep + rest.replace(hostname, ip, 1)


def _extract_hostname(host):
    """Strip ldap[s]:// scheme and any trailing :port, return bare hostname."""
    h = host
    if '://' in h:
        h = h.split('://', 1)[1]
    if ':' in h:
        h = h.rsplit(':', 1)[0]
    return h


def _parse_username_and_domain(args):
    """Return (raw_username_for_ADAuthentication, domain)."""
    username = args.username
    if username is None:
        return None, args.domain or ''
    if '\\' in username:
        raise AuthError(
            'username must be in UPN format (user@domain), or use --domain. '
            'Down-level DOMAIN\\user is no longer supported.')
    if '@' in username:
        return username, username.rsplit('@', 1)[1]
    if args.domain:
        return username, args.domain
    raise AuthError('username must include a realm (user@domain) or use --domain')


def _kerberos_attempt_anticipated(args):
    """Will build_connection attempt Kerberos at all?"""
    if args.username is None:
        return False
    if args.auth_method == 'ntlm':
        return False
    if args.auth_method == 'kerberos':
        return True
    # auto: attempt Kerberos if any credential source is present
    import os
    return bool(args.kerberos
                or os.getenv('KRB5CCNAME')
                or args.password
                or args.hashes
                or args.aesKey)


def build_connection(args):
    """Build and bind an ldap3.Connection from parsed CLI args. Raises AuthError."""
    username, domain = _parse_username_and_domain(args)

    hostname = _extract_hostname(args.host)

    if (_kerberos_attempt_anticipated(args) and _IP_RE.match(hostname)
            and args.auth_method == 'auto' and not args.kerberos and not args.aesKey):
        # Kerberos cannot work against an IP, but NTLM can: don't fail in auto mode
        print('[*] IP address given, using NTLM (Kerberos needs the DC FQDN)')
        args.auth_method = 'ntlm'
    if _kerberos_attempt_anticipated(args) and _IP_RE.match(hostname):
        raise AuthError(
            'host %s looks like an IP but Kerberos requires a hostname (FQDN). '
            'Add it to /etc/hosts if it does not resolve.' % hostname)

    # Down-level domain (CORP) and DC given by FQDN: use the DC's DNS domain as realm
    if (getattr(args, 'domain_from_username', False) and domain and '.' not in domain
            and not _IP_RE.match(hostname) and '.' in hostname):
        domain = hostname.split('.', 1)[1]

    # -n/--dns-server: resolve the DC hostname with that server and connect to its IP
    kdc = hostname
    dns_server = getattr(args, 'dns_server', None)
    if dns_server and not _IP_RE.match(hostname):
        kdc = _resolve(hostname, dns_server)
        print('[*] %s resolved to %s' % (hostname, kdc))
        args.tls_names = [hostname]
        args.host = _replace_hostname(args.host, hostname, kdc)

    server = _build_server(args)

    lm_hash = ''
    nt_hash = ''
    if args.hashes:
        lm_part, nt_part = args.hashes.split(':', 1)
        lm_hash = lm_part
        nt_hash = nt_part

    auth = ADAuthentication(
        username=username or '',
        password=args.password or '',
        domain=domain,
        auth_method=args.auth_method,
        ldap_channel_binding=args.ldap_channel_binding,
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        aeskey=args.aesKey or '',
        use_ccache=bool(args.kerberos),
        start_tls=getattr(args, 'start_tls', False),
    )
    auth.set_kdc(kdc)
    if args.aesKey:
        auth.set_aeskey(args.aesKey)

    return auth.authenticate(server, hostname)
