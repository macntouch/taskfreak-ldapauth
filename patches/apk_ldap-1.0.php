<?php

/**
 *
 * Copyright (c) 2009, Thomas Chemineau - thomas.chemineau<at>gmail.com
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   * Neither the name of the AEPIK.NET nor the names of its contributors may
 *     be used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @package    Aepik LDAP Framework
 * @author     Thomas Chemineau <thomas.chemineau@gmail.com>
 * @copyright  2009 - Thomas Chemineau
 * @license    BSD
 * @link       http://www.aepik.net/
 * @version    1.0
 */

/* ------------------------------------------------------------------------ *\
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

Note :
  If you decide to use SSL, be sure that PHP trusts certificate from the LDAP
  server. This could be done on Linux system by editing /etc/ldap.conf or
  /etc/ldap/ldap.conf (depends of OS), and adding the following line (or
  equivalent by configuration ) :
    TLS_REQCERT never
\* ------------------------------------------------------------------------ */

/**
 * LDAP Connection
 * connects to LDAP database
 * @author   Thomas Chemineau <thomas.chemineau@gmail.com>
 */

class Apk_LdapConnection
{
	var $_ldapServer ;
	var $_ldapBindDn ;
	var $_ldapBinPw ;
	var $_ldapBaseDn ;
	var $_ldapLink ;

    /*
     * Create a new Apk_LdapConnection object.
     * @param string $server Ldap server
     * @param string $binddn Ldap Bind DN
     * @param string $bindpw Ldap Bind password
     */
	function Apk_LdapConnection($server=null, $binddn=null, $bindpw=null)
    {
        if ($server && $binddn && $bindpw)
        {
            $this->_ldapServer = $server ;
            $this->_ldapBindDn = $binddn ;
            $this->_ldapBindPw = $bindpw ;
        }
        else
        {
            $this->_ldapServer = APK_LDAP_SERVER ;
            $this->_ldapBindDn = APK_LDAP_BINDDN ;
            $this->_ldapBindPw = APK_LDAP_BINDPW ;
        }
	}

    /*
     * Authenticate a user to the Ldap directory.
     * @param string $username The username to authenticate
     * @param string $password The corresponding password
     * @param string $basedn The Ldap search base DN
     * @param string $filter The Ldap filter containing '%s' string, which will
     *      be replace by username
     * @param string $scope The Ldap scope (one, sub, base)
     * @return boolean
     */
    function authenticate(
            $username ,
            $password ,
            $filter = APK_LDAP_FILTER ,
            $basedn = APK_LDAP_BASEDN ,
            $scope  = APK_LDAP_SCOPE
        )
    {
        if($this->_ldapLink)
        {
            //
            // Here, we try to retrieve the user DN corresponding to the
            // username provided by the user on the form. We use a filter
            // defined above to achieve that. If we have result, then we get
            // only the first entry. So, understand that username MUST be
            // unique.
            //
            $filter = $this->getFormatedFilter($username, $filter) ;
            $usersdn = $this->searchDn($filter, $basedn, $scope) ;
            //
            // In this entry, we found the DN of the user's LDAP entry.
            // We will use it to authenticate the user.
            // If the bind succeed, then user is logged in. In the other
            // way, the password mismatched on the LDAp directory.
            //
            if (is_array($usersdn))
            {
                $userdn = $usersdn[0] ;
                if (@ldap_bind($this->_ldapLink, $userdn, $password))
                {
                    return true ;
                }
            }
        }
        return false ;
    }

    /*
     * Connect to the Ldap directory.
     * @param int $version The version of the Ldap protocol to use
     * @param boolean $ssl Specify if we open SSL connection or not
     * @return boolean
     */
	function connect($version=APK_LDAP_VERSION, $ssl=APK_LDAP_USESSL)
    {
        if (!$this->_ldapLink)
        {
            //
            // We can connect to LDAP server by SSL. We check first on TLS.
            // If TLS does not work, we try to use SSL. For information, TLS
            // is an extention of LDAP directory to do SSL over
            // normal connection.
            //
            if ($ssl)
            {
                $this->_ldapLink = @ldap_connect($this->_ldapServer) ;
                if ($this->_ldapLink && !@ldap_start_tls($this->_ldapLink))
                {
                    $this->disconnect() ;
                    $this->_ldapServer = preg_replace('#ldaps?://#', '', $this->_ldapServer) ;
                    $this->_ldapServer = 'ldaps://' . $this->_ldapServer ;
                    if (preg_match('/:[0-9]+/', $this->_ldapServer) == 0)
                    {
                        $this->_ldapServer .= ':636' ;
                    }
                }
            }
            if (!$this->_ldapLink)
            {
                $this->_ldapLink = @ldap_connect($this->_ldapServer) ;
            }
            if ($this->_ldapLink === false)
            {
                die('Cannot connect to Ldap server') ;
                return false ;
            }
            //
            // The next step is to connect to the LDAP directory. This is
            // done by setting protocol version (version 2 by default with
            // PHP), and do a bind, anonymously or not, to acquire future search
            // priveleges.
            //
            if ($version == 3)
            {
                ldap_set_option($this->_ldapLink, LDAP_OPT_PROTOCOL_VERSION, 3) ;
            }
            if (!is_null($this->_ldapBindDn) && !is_null($this->_ldapBindPw))
            {
                if (!@ldap_bind($this->_ldapLink, $this->_ldapBindDn, $this->_ldapBindPw))
                {
                    die('Cannot bind to Ldap server') ;
                    return false ;
                }
            }
            else
            {
                if (!@ldap_bind($this->_ldapLink))
                {
                    die('Cannot bind anonymously to Ldap server') ;
                    return false ;
                }
            }
        }
        return true;
    }

    /*
     * Close this Ldap connection.
     * @return boolean
     */
    function disconnect()
    {
        if ($this->_ldapLink)
        {
            ldap_close($this->_ldapLink) ;
            $this->_ldapLink = NULL ;
            return true ;
        }
        return false ;
    }

    /*
     * Test if Ldap connection is opened.
     * @return boolean
     */
    function isConnected()
    {
        if ($this->_ldapLink)
        {
            return true;
        }
        return false;
    }

    /*
     * Formate the user filter.
     * @return String
     */
    function getFormatedFilter($username, $filter = APK_LDAP_FILTER)
    {
        return preg_replace("/\%s/", $username, $filter) ;
    }

    /*
     * Search for LDAP entries.
     * @return Array or false if failed.
     */
    function search(
            $filter ,
            $attributes = array() ,
            $basedn = APK_LDAP_BASEDN ,
            $scope  = APK_LDAP_SCOPE
        )
    {
        if($this->_ldapLink)
        {
            if (sizeof($attributes) == 0)
            {
                $attributes[] = 'dn' ;
            }
            switch ($scope)
            {
                case "one" :
                    $search_result = @ldap_list($this->_ldapLink, $basedn, $filter, $attributes) ;
                    break ;
                case "base" :
                    $search_result = @ldap_read($this->_ldapLink, $basedn, $filter, $attributes) ;
                    break ;
                default :
                    $search_result = @ldap_search($this->_ldapLink, $basedn, $filter, $attributes) ;
                    break ;
            }
            if (!$search_result)
            {
                return false ;
            }
            $entries = @ldap_get_entries($this->_ldapLink, $search_result) ;
            if (is_array($entries) && sizeof($entries)>0)
            {
               return $entries ;
            }
        }
        return false ;
    }

    /*
     * Search an entry and return its DN.
     * @return String or false if failed.
     */
    function searchDn(
            $filter ,
            $basedn = APK_LDAP_BASEDN ,
            $scope  = APK_LDAP_SCOPE
        )
    {
        if($this->_ldapLink)
        {
            $entries = $this->search($filter, array('dn'), $basedn, $scope);
            if (is_array($entries))
            {
                $entriesb = array() ;
                foreach ($entries as $index => $values)
                    if (is_array($values) && !is_null($values['dn']))
                        $entriesb[] = $values['dn'] ;
                return $entriesb ;
            }
        }
        return false ;
    }

}

