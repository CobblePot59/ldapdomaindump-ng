import argparse
import json
import os.path
import re
from time import strftime, gmtime

class PrettyOuput():

    # pwdProperties as a 6 bit string, most significant bit first
    # (REFUSE_PASSWORD_CHANGE ... PASSWORD_COMPLEX)
    def d2b(self, a):
        return format(int(a) & 0x3f, '06b')

    def convert(self, time):
        if time is None:
            return "Not Set"
        if isinstance(time, str):
            # ldap3 >= 2.6 serializes intervals as str(timedelta), e.g. "42 days, 0:00:00"
            m = re.match(r'^(?:(\d+) days?, )?(\d+):(\d+):(\d+)(?:\.\d+)?$', time.strip())
            if not m:
                return time
            days, hrs, mins, secs = (int(x or 0) for x in m.groups())
            # timedelta.max is used by ldap3 for the special "never" value
            if days >= 999999999:
                return "Not Set"
            time = -((((days * 24 + hrs) * 60 + mins) * 60 + secs) * 10000000)
        if time == 0:
            return "None"
        if time == -9223372036854775808:
            return "Not Set"
        sec = abs(time) // 10000000
        days = sec // 86400
        sec -= 86400*days
        hrs = sec // 3600
        sec -= 3600*hrs
        mins = sec // 60
        sec -= 60*mins
        result = ""
        if days > 1:
            result += "{0} days ".format(days)
        elif days == 1:
            result += "{0} day ".format(days)
        if hrs > 1:
            result += "{0} hours ".format(hrs)
        elif hrs == 1:
            result += "{0} hour ".format(hrs)
        if mins > 1:
            result += "{0} minutes ".format(mins)
        elif mins == 1:
            result += "{0} minute ".format(mins)
        if not result:
            result = "{0} seconds".format(sec)
        return result.strip()

    def password_complexity(self, data):

        print('''
    +-----------------------------------------+
    | Password Policy Information             |
    +-----------------------------------------+
    ''')

        print("[+] Password Info for Domain:", data[0]['attributes']['dc'][0].upper())
        print("\t[+] Minimum password length:", data[0]['attributes']['minPwdLength'][0])
        print("\t[+] Password history length:", data[0]['attributes']['pwdHistoryLength'][0])

        password_properties = self.d2b(data[0]['attributes']['pwdProperties'][0])
        print("\t[+] Password Complexity Flags:", password_properties)
        print("")
        print("\t\t[+] Domain Refuse Password Change:", password_properties[0])
        print("\t\t[+] Domain Password Store Cleartext:", password_properties[1])
        print("\t\t[+] Domain Password Lockout Admins:", password_properties[2])
        print("\t\t[+] Domain Password No Clear Change:", password_properties[3])
        print("\t\t[+] Domain Password No Anon Change:", password_properties[4])
        print("\t\t[+] Domain Password Complex:", password_properties[5])
        print("")
        attrs = data[0]['attributes']
        get = lambda name: attrs[name][0] if attrs.get(name) else None
        print("\t[+] Maximum password age:", self.convert(get('maxPwdAge')))
        print("\t[+] Minimum password age:", self.convert(get('minPwdAge')))
        print("\t[+] Reset Account Lockout Counter:", self.convert(get('lockOutObservationWindow')))
        print("\t[+] Locked Account Duration:", self.convert(get('lockoutDuration')))
        print("\t[+] Account Lockout Threshold:", get('lockoutThreshold'))
        print("\t[+] Forced Log off Time:", self.convert(get('forceLogoff')))

    def domain_info(self, data):
        print('''
    +--------------------------------------+
    | Getting Domain Sid For               |
    +--------------------------------------+
    ''')
        print('[+] Domain Name:', data[0]['attributes']['dc'][0])
        print('Domain Sid:', data[0]['attributes']['objectSid'][0])
        print('')
        return data[0]['attributes']['dc'][0]

    def user_info(self, users, dc):
        print('''
    +------------------------+
    | Users Infos            |
    +------------------------+
    ''')
        for user in users:
            desc = user['attributes'].get('description')[0] if user['attributes'].get('description') else "(null)"
            print("Account: " + dc + "\\" + user['attributes']['sAMAccountName'][0] + "\tName: " + user['attributes']['name'][0] + "\tDesc: " + desc)

        print("")
        for user in users:
            print("user:[" + user['attributes']['sAMAccountName'][0] + "]")
        print("")

    def groups_info(self, groups, dc):
        print('''
    +------------------------+
    | Groups Infos           |
    +------------------------+
    ''')
        for group in groups:
            print("group:[" + group['attributes']['name'][0] + "]")

        for group in groups:
            if group['attributes'].get('member'):
                users = re.findall(r"^CN=([\w\s\-\_\{\}\.\$\#]+)", '\n'.join(group['attributes']['member']), re.M)
                if users:
                    print("\n[+] Getting domain group memberships:")
                    for user in users:
                        if user == "S-1-5-11":
                            user = "NT AUTHORITY\\Authenticated Users"
                        elif user == "S-1-5-4":
                            user = "NT AUTHORITY\\INTERACTIVE"
                        elif user == "S-1-5-17":
                            user = "NT AUTHORITY\\IUSR"
                        print("Group '" + group['attributes']['name'][0] + "' has member: " + dc + "\\" + user)

def main():
    parser = argparse.ArgumentParser(description='LDAPDomainDump to pretty output like enum4linux.')

    #Main parameters
    parser.add_argument("-d", "--directory", help="The ldapdomaindump directory where the json files are saved. Required files: domain_users.json, domain_groups.json and domain_policy.json")
    args = parser.parse_args()

    if args.directory:
        with open(args.directory + '/domain_policy.json') as f:
            domain = json.load(f)
        with open(args.directory + '/domain_users.json') as f:
            users = json.load(f)
        with open(args.directory + '/domain_groups.json') as f:
            groups = json.load(f)
        pretty = PrettyOuput()
        dc = pretty.domain_info(domain)
        pretty.password_complexity(domain)
        pretty.user_info(users, dc.upper())
        pretty.groups_info(groups, dc.upper())
    else:
        print("Missing parameter --directory /output/")

if __name__ == "__main__":
    main()
