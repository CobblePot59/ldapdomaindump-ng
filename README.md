# ldapdomaindump-ng
Active Directory information dumper via LDAP, based on [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) by [Dirk-jan Mollema](https://github.com/dirkjanm).

Any authenticated domain user can read a lot of information over LDAP. ldapdomaindump-ng collects it and writes it as a readable HTML report, JSON and greppable files.

## What's new compared to ldapdomaindump
- **Authentication**: Kerberos (ccache, password, NT hash, AES key, cross-realm) ported from [BloodHound.py](https://github.com/dirkjanm/BloodHound.py), automatic fallback to NTLM, pass-the-hash with `--hashes`, StartTLS, LDAP channel binding, `DOMAIN\user`, `DOMAIN/user` or `user@domain` usernames, DC hostname resolved with `-n`, NTLM on Python/OpenSSL versions without MD4
- **Collection**: domain and forest details, domain controllers, FSMO roles, sites, OUs, GPOs, AD integrated DNS, PKI, managed service accounts, contacts, foreign security principals, and more account attributes (UPN, manager, replicated last logon, encryption types, delegation, LAPS presence)
- **HTML report**: single self-contained report with navigation, overview page, filtering, sorting, column chooser, CSV export, OU tree, organization chart, group membership explorer and dark mode
- **Output**: choice of formats with `-f`, one file per format with `--single-file`
- **Fixes**: wrong password policy values in `ldd2pretty`, "never" intervals shown as huge numbers, unescaped directory values in the HTML report

New columns are appended at the end of the greppable files, so existing scripts keep working.

## Installation
Python 3.6 or greater is required.
```
pip install .
```
NTLM signing and channel binding need the [ly4k/ldap3](https://github.com/ly4k/ldap3) fork, which is the ldap3 version referenced by `pyproject.toml`.

## Usage
Run `ldapdomaindump-ng` once installed, `python -m ldapdomaindump`, or `python ldapdomaindump-ng.py` from the source.

```
usage: ldapdomaindump-ng.py [-h] [-u USERNAME] [-p PASSWORD] [--domain DOMAIN]
                            [--auth-method {auto,ntlm,kerberos}] [-k]
                            [--hashes LMHASH:NTHASH] [-aesKey HEXKEY]
                            [-no-pass] [--start-tls] [--ldap-channel-binding]
                            [--no-tls-verify] [-o DIRECTORY] [-f FORMATS]
                            [--single-file] [--grouped-json] [-d DELIMITER]
                            [-r] [-n DNS_SERVER] [-m] [--debug]
                            HOSTNAME

ldapdomaindump-ng: Active Directory information dumper via LDAP. Dumps users, groups, computers,
OUs, GPOs, DNS, PKI and more to HTML/JSON/greppable output.

Required options:
  HOSTNAME              Hostname/ip or ldap://host:port connection string to
                        connect to (use ldaps:// to use SSL)

Main options:
  -h, --help            show this help message and exit

Authentication options:
  -u, --username, --user USERNAME
                        Username: user@domain (UPN), DOMAIN\user or
                        DOMAIN/user. Leave empty for anonymous bind
  -p, --password PASSWORD
                        Password for authentication. Prompted if not specified
                        (unless -no-pass, -k, --hashes or -aesKey is used)
  --domain DOMAIN       Domain/realm, used when the username does not contain
                        one
  --auth-method {auto,ntlm,kerberos}
                        Authentication method (default: auto, try Kerberos
                        first and fall back to NTLM)
  -k, --kerberos        Use Kerberos authentication with the ticket from the
                        KRB5CCNAME ccache. Implies --auth-method kerberos
  --hashes LMHASH:NTHASH
                        NTLM hashes in LM:NT format (LM can be blank: :NT).
                        The NT hash is also usable as an RC4 key for Kerberos
  -aesKey HEXKEY        AES128 (32 hex) or AES256 (64 hex) Kerberos key
  -no-pass              Don't prompt for a password (useful with -k, --hashes
                        or -aesKey)

Connection options:
  --start-tls           Upgrade plain LDAP to TLS with StartTLS before binding
                        (not compatible with ldaps://)
  --ldap-channel-binding
                        Use LDAP channel binding (EPA, RFC 5929 tls-server-
                        end-point) over ldaps:// or StartTLS, for NTLM and
                        Kerberos
  --no-tls-verify       Disable TLS certificate validation (insecure, for
                        self-signed DC certificates)

Output options:
  -o, --outdir DIRECTORY
                        Directory in which the dump will be saved (default:
                        current)
  -f, --format FORMATS  Output formats to generate, comma separated or
                        repeated: html, json, grep or all (default: all).
                        Example: -f html,json
  --single-file         Write a single file per output format
                        (domain_dump.html/.json/.grep) instead of one file per
                        report
  --grouped-json        Also write json files for grouped files (default:
                        disabled)
  -d, --delimiter DELIMITER
                        Field delimiter for greppable output (default: tab)

Misc options:
  -r, --resolve         Resolve computer hostnames (might take a while and
                        cause high traffic on large networks)
  -n, --dns-server DNS_SERVER
                        DNS server used to resolve the DC hostname and
                        computer hostnames (try a domain controller IP)
  -m, --minimal         Only query minimal set of attributes to limit memmory
                        usage
  --debug               Enable verbose debug logging (auth flow and ldap3
                        EXTENDED logs)

examples:
  ldapdomaindump-ng.py -u user@corp.local -p 'Passw0rd' dc01.corp.local
  ldapdomaindump-ng.py -u 'CORP\user' -p 'Passw0rd' 10.0.0.10
  ldapdomaindump-ng.py -u user@corp.local --hashes :<NThash> dc01.corp.local
  ldapdomaindump-ng.py -u user@corp.local -k -no-pass dc01.corp.local     (KRB5CCNAME=user.ccache)
  ldapdomaindump-ng.py -u user@corp.local -aesKey <hexkey> dc01.corp.local
  ldapdomaindump-ng.py -u user@corp.local -p 'Passw0rd' --ldap-channel-binding ldaps://dc01.corp.local
```

Notes:
- `--auth-method auto` (default) tries Kerberos first and falls back to NTLM. Kerberos needs the DC hostname, not its IP; use `-n` if your DNS does not resolve it.
- If the DC enforces LDAP signing, use Kerberos, `ldaps://` or `--start-tls`.
- Quote `'DOMAIN\user'` (the shell removes an unquoted backslash) or use `DOMAIN/user`.
- `-r` resolves every computer hostname, which can be slow and load the DC; `domain_dns` usually gives the same information without any query.
- `--minimal` only requests the attributes shown in the HTML and greppable files, to limit memory usage on large domains.

## Reports
| Report | Content |
|---|---|
| `index` | Overview (HTML only) |
| `domain_info` | Domain and forest, domain controllers, FSMO roles, sites, subnets, site links |
| `domain_users` / `domain_groups` / `domain_computers` | Accounts |
| `domain_policy` / `domain_trusts` | Password policy, domain trusts |
| `domain_ous` / `domain_gpos` | OU tree with linked GPOs, group policy objects |
| `domain_dns` | AD integrated DNS zones and records |
| `domain_pki` | Certificate authorities and templates |
| `domain_services` | Managed service accounts, SPNs by service |
| `domain_contacts` / `domain_foreign` | Contacts, foreign security principals |
| `domain_users_by_group` / `domain_computers_by_os` | Grouped views (JSON only with `--grouped-json`) |
| `domain_orgchart` / `domain_membership` | Organization chart, group membership explorer (HTML only) |

With `--single-file`, everything goes to `domain_dump.html`, `domain_dump.json` and `domain_dump.grep`.

## Utilities
- `ldd2bloodhound` converts the JSON files to CSV for BloodHound 1.x. For current BloodHound versions, use [BloodHound.py](https://github.com/dirkjanm/BloodHound.py).
- `ldd2pretty` prints the JSON files in an enum4linux like format.

## Credits
- [Dirk-jan Mollema](https://github.com/dirkjanm): ldapdomaindump and BloodHound.py
- [bandrel](https://github.com/bandrel): Kerberos, StartTLS, channel binding and debug support
- the ldapdomaindump contributors

## License
MIT, see [LICENSE](LICENSE).
