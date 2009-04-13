---[find]---
define('TZN_USER_PASS_MODE',4);
---[replace]---
define('TZN_USER_PASS_MODE',5);

---[find]---
// === CONTEXTS ===============================================

$GLOBALS['confContext'] = array(
    1 => '#939',
    2 => '#c33',
    3 => '#66f',
    4 => '#090',
    5 => '#963',
    6 => '#39c',
    7 => '#3c9',
    8 => '#999'
);
---[replace]---
// === CONTEXTS ===============================================

$GLOBALS['confContext'] = array(
    1 => '#939',
    2 => '#c33',
    3 => '#66f',
    4 => '#090',
    5 => '#963',
    6 => '#39c',
    7 => '#3c9',
    8 => '#999'
);

// === LDAP AUTHENTICATION PLUGIN =============================

define("APK_LDAP_SERVER", "localhost") ;
define("APK_LDAP_BASEDN", "ou=people,dc=example,dc=com" ) ;
define("APK_LDAP_BINDDN", "cn=admin,dc=example,dc=com") ;
define("APK_LDAP_BINDPW", "admin") ;
define("APK_LDAP_FILTER", "(uid=%s)" ) ;
define("APK_LDAP_SCOPE", "one" ) ;
define("APK_LDAP_VERSION", 3) ;
define("APK_LDAP_USESSL", false) ;
define("APK_LDAP_AUTO_USERCREATED", FALSE) ;
define("APK_LDAP_AUTO_USERENABLED", TRUE);
define("APK_LDAP_AUTO_USERLEVEL", 2);   // guest=1, user=2, manager=3, admin=4

$GLOBALS['confLdapAttributesMapping'] = array(
        'firstName' => 'givenName' ,
        'lastName' => 'sn' ,
        'email' => 'mail' ,
        'username' => 'uid' ,
//      'title' => 'title' ,
//      'city' => 'l' ,
//      'countryId' => 'c' ,
    ) ;

