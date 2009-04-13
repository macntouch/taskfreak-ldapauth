--------------------------------------------------------------------------------

    PATCHING TASKFREAK TO ENABLE LDAP AUTHENTICATION - last update 10/04/2009
           AUTHOR(S) : Thomas Chemineau <thomas.chemineau@gmail.com>

--------------------------------------------------------------------------------




1. Informations

  Requires:
    Taskfreak 0.6.1 or 0.6.2
    Taskfreak Plugin Manager 0.2.6

  This patch has been tested on TaskFreak 0.6.1 and TaskFreak 0.6.2, both multi-
  user support. Your PHP version must have the LDAP module loaded.

  Read carefully all this document :
    - Section 2 will explain how to patch TaskFreak source ;
    - Section 3 will explain how all works.

  Finaly, the first Taskfreak Administrator can authenticate itself as long as
  its password is empty (the default usecase into Taskfreak!). So, take care to
  define an LDAP user as administrator manually.




2. Patching instructions

  Here are instructions to patch applying patches :

    $ cd /path/to/taskfreak/include
    $ patch -p0 < /path/to/taskfreak-ldap-0.2/config.php-0.6.2.patch
    $ cd /path/to/taskfreak/include/classes
    $ cp /path/to/taskfreak-ldap-0.2/apk_ldap-1.0.php ./apk_ldap.php
    $ patch -p0 < /path/to/taskfreak-ldap-0.2/tzn_user-1.4.patch

  Then, edit the config.php file to configure LDAP parameters. The filter is
  very important. Do not forget to put the %s string, it will be replace by
  the username that fill the user.

    define("APK_LDAP_FILTER", "(uid=%s)");

  Finaly, to enable LDAP authentication, just modify the TZN_USER_PASS_MODE
  constant and put the value 5.

    define('TZN_USER_PASS_MODE',5);

  That's done.

  You can then enable the auto user creation, by putting TRUE into the
  APK_LDAP_AUTO_USERCREATED.

    define('APK_LDAP_AUTO_CREATED', TRUE);

  Mapping between Taskfreak user fields and LDAP attributes is done by
  configuring the $GLOBALS['confLdapAttributesMapping'].

    $GLOBALS['confLdapAttributesMapping'] = array(
        'firstName' => 'givenName' ,
        'lastName' => 'sn' ,
        'email' => 'mail' ,
        'username' => 'uid' ,
//      'title' => 'title' ,
//      'city' => 'l' ,
//      'countryId' => 'c' ,
    ) ;




3. Exploitation

  You have to create user account into Taskfreak for each LDAP user you want,
  take care about the login. This login is the link between the LDAP account
  and the Taskfreak account. The password you give for this new user will never
  been tested.

  For example, I have a user into my LDAP directory, represented by the DN
  'cn=user1,ou=people,dc=example,dc=com'. In this LDAP entry, I have an
  attribute named 'uid' with the value 'user1'. So, I authenticate myself into
  Taskfreak and create an account where username is 'user1'. I have to put also
  a password, but it will never been tested. Only the LDAP authentication
  operation will be used. In this example, understand that my LDAP filter is
  '(uid=%s)', so the LDAP directory will give me the correct DN corresponding
  to the user I want to log in.

  With OpenLDAP Directory server, you should obtain something like that in
  Stats LogLevel :

    conn=1 fd=17 ACCEPT from IP=127.0.0.1:34018 (IP=0.0.0.0:389)
    conn=1 op=0 BIND dn="cn=manager,dc=example,dc=com" method=128
    conn=1 op=0 BIND dn="cn=manager,dc=example,dc=com" mech=SIMPLE ssf=0
    conn=1 op=0 RESULT tag=97 err=0 text=
    conn=1 op=1 SRCH base="ou=people,dc=example,dc=com" scope=1 deref=0 filter="(uid=user1)"
    conn=1 op=1 SRCH attr=dn
    conn=1 op=1 SEARCH RESULT tag=101 err=0 nentries=1 text=
    conn=1 op=2 BIND anonymous mech=implicit ssf=0
    conn=1 op=2 BIND dn="cn=user1,ou=people,dc=example,dc=com" method=128
    conn=1 op=2 BIND dn="cn=user1,ou=people,dc=example,dc=com" mech=SIMPLE ssf=0
    conn=1 op=2 RESULT tag=97 err=0 text=
    conn=1 op=3 UNBIND
    conn=1 fd=17 closed

  If you decide to use SSL, be sure that PHP trusts certificate from the LDAP
  server. This could be simply done on Linux system by editing /etc/ldap.conf
  or /etc/ldap/ldap.conf (depends of OS), and adding the following line (or
  equivalent by configuration ) :

    TLS_REQCERT never



