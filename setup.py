from setuptools import setup
setup(name='ldapdomaindump-ng',
      version='1.0.0',
      description='Active Directory information dumper via LDAP (next generation of ldapdomaindump)',
      author='Dirk-jan Mollema',
      author_email='dirkjan@dirkjanm.io',
      url='https://github.com/CobblePot59/ldapdomaindump-ng',
      packages=['ldapdomaindump'],
      requires_python=">=3.6",
      install_requires=['dnspython', 'impacket>=0.9.17', 'ldap3>=2.5,!=2.5.2,!=2.5.0,!=2.6', 'pyasn1>=0.4', 'pycryptodome'],
      package_data={'ldapdomaindump': ['style.css', 'report.js']},
      include_package_data=True,
      entry_points= {
        'console_scripts': ['ldapdomaindump-ng=ldapdomaindump:main','ldd2bloodhound=ldapdomaindump.convert:ldd2bloodhound','ldd2pretty=ldapdomaindump.pretty:main']
      },
      license="MIT",
      )
