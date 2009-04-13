---[find]---
					case 4:
						$this->password = "MD5('$pass1')";
						break;
---[replace]---
					case 4:
						$this->password = "MD5('$pass1')";
						break;
                    // 8<---- LDAP AUTHENTICATION PLUGIN --
                    case 5:
                        // $this->password = "MD5('$pass1')";
                        return false ;
                        break;
                    // 8<---- LDAP AUTHENTICATION PLUGIN --
---[find]---
		case 4:
			if (!$this->password && !$password) {
				break;
			}
			$strSql = "SELECT MD5('$password') as passHash";
            if ($result = $this->query($strSql)) {
                if ($row = $result->rNext()) {
                    if ($row->passHash == $this->password) {
                        // password OK
                        break;
                    }
                }
            }
            $this->_error['login'] = 
            	$GLOBALS["langTznUser"]["user_pass_invalid"];
            $this->zBadAccess();
            return false; // error or password mismatch
            break;
---[replace]---
		case 4:
			if (!$this->password && !$password) {
				break;
			}
			$strSql = "SELECT MD5('$password') as passHash";
            if ($result = $this->query($strSql)) {
                if ($row = $result->rNext()) {
                    if ($row->passHash == $this->password) {
                        // password OK
                        break;
                    }
                }
            }
            $this->_error['login'] = 
            	$GLOBALS["langTznUser"]["user_pass_invalid"];
            $this->zBadAccess();
            return false; // error or password mismatch
            break;
        // 8<---- LDAP AUTHENTICATION PLUGIN --
        case 5:
            if (!$this->password && !$password) {
                break;
            }
            require_once dirname(__FILE__) . '/apk_ldap.php' ;
            $ldap = new Apk_LdapConnection() ;
            if ($ldap->connect())
            {
                $res = $ldap->authenticate($this->username, $password) ;
                $ldap->disconnect() ;
            }
            return $res ;
            break ;
        // 8<---- LDAP AUTHENTICATION PLUGIN --
---[find]---
    function login($username, $password, $level=null) {
        if ($username == '') {
            $this->_error['login'] = $GLOBALS["langTznUser"]["user_name_empty"];
            return false;
        }
        if (!preg_match(TZN_USER_NAME_REGEXP, $username)) {
        	$this->_error['login'] = $GLOBALS['langTznUser']['user_name_invalid'];
        	return false;
        }
        if ($this->loadByKey(TZN_USER_LOGIN,$username)) {
            if (($level!=null) && (!$this->getLvl($level))) {
                //Insufficient rights
                $this->_error['login'] = 
                	$GLOBALS["langTznUser"]["user_forbidden"];
            }
            if (!$this->enabled) {
                //Account Disabled
                $this->_error['login'] = 	
                	$GLOBALS["langTznUser"]["user_disabled"];
            }
            if (!$this->zCheckPassword($password)) {
                $this->_error['login'] = 	
                	$GLOBALS["langTznUser"]["user_password_invalid"];
            }
			if (count($this->_error)) {
				$this->zBadAccess();
				return false;
			}
        } else {
---[replace]---
    function login($username, $password, $level=null) {
        if ($username == '') {
            $this->_error['login'] = $GLOBALS["langTznUser"]["user_name_empty"];
            return false;
        }
        if (!preg_match(TZN_USER_NAME_REGEXP, $username)) {
        	$this->_error['login'] = $GLOBALS['langTznUser']['user_name_invalid'];
        	return false;
        }
        if ($this->loadByKey(TZN_USER_LOGIN,$username)) {
            if (($level!=null) && (!$this->getLvl($level))) {
                //Insufficient rights
                $this->_error['login'] = 
                	$GLOBALS["langTznUser"]["user_forbidden"];
            }
            if (!$this->enabled) {
                //Account Disabled
                $this->_error['login'] = 	
                	$GLOBALS["langTznUser"]["user_disabled"];
            }
            if (!$this->zCheckPassword($password)) {
                $this->_error['login'] = 	
                	$GLOBALS["langTznUser"]["user_password_invalid"];
            }
			if (count($this->_error)) {
				$this->zBadAccess();
				return false;
			}
        } else {
            // 8<---- LDAP AUTHENTICATION PLUGIN --
            if (TZN_USER_PASS_MODE == '5')
            {
                // Security tricks, to avoid indefinite loops on user creation,
                // we put a random value into $GLOBALS['confLdapAutoCreateStatus']
                // and just test if this array key exists. If so, we already
                if (array_key_exists('confLdapAutoCreateStatus', $GLOBALS))
                {
                    return false ;
                }
                $GLOBALS['confLdapAutoCreateStatus'] = 0 ;
                if ($this->autoCreateFromLdap($username,$password) === true)
                {
                    return $this->login($username,$password,$level);
                }
            }
            // 8<---- LDAP AUTHENTICATION PLUGIN --
---[find]---
    function resetAutoLogin() {
        if ($this->id) {
            setCookie('autoLogin');
            if ($this->autoLogin) {
	            $this->autoLogin = "0";
    	        $this->update("autoLogin");
    	    }
            return true;
        }
        return false;
    }
---[replace]---
    function resetAutoLogin() {
        if ($this->id) {
            setCookie('autoLogin');
            if ($this->autoLogin) {
	            $this->autoLogin = "0";
    	        $this->update("autoLogin");
    	    }
            return true;
        }
        return false;
    }

    // 8<---- LDAP AUTHENTICATION PLUGIN --
    /**
     * Check if we use LDAP authentication backend. If so, then trying
     * to retrieve the user from the LDAP directory. If found, we auto
     * create it into Taskfreak. Some attributes have to be defined
     * previously into the LDAP directory.
     * @return boolean
     */
    function  autoCreateFromLdap($username, $password)
    {
        if (!APK_LDAP_AUTO_USERCREATED)
        {
          return false ;
        }
        require_once dirname(__FILE__) . '/apk_ldap.php' ;
        $ldap = new Apk_LdapConnection() ;
        if ($ldap->connect())
        {
            $filter = $ldap->getFormatedFilter($username) ;
            $usersdn = $ldap->searchDn($filter) ;
            if (is_array($usersdn))
            {
                $userldap = $ldap->search($filter,
                        array_values($GLOBALS['confLdapAttributesMapping']),
                        $usersdn[0], 'base') ;
            }
            $ldap->disconnect() ;
        }
        if (sizeof($userldap)>1)
        {
            $userldap = $userldap[0] ;
            foreach ($GLOBALS['confLdapAttributesMapping'] as $field => $attr)
            {
                $userdata[$field] = $userldap[strtolower($attr)][0] ;
            }
            if (!array_key_exists('countryId', $userdata))
            {
                $userdata['countryId'] = FRK_DEFAULT_COUNTRY ;
            }
            $objEditItem = new Member();
            $objEditItem->initObjectProperties();
            $objEditItem->setAuto($userdata);
            $objEditItem->level = APK_LDAP_AUTO_USERLEVEL ;
            $objEditItem->enabled = APK_LDAP_AUTO_USERCREATED ? '1' : '0' ;
            $objEditItem->author->id = 1 ;
            $objEditItem->password = $this->getRdm(
                    TZN_USER_PASS_MAX, "1234567890"
                    ."abcdefghijklmnopqrstuvwxyz"
                    ."ABCDEFGHIJKLMNOPQRSTUVWXYZ") ;
            if ($objEditItem->add()>1)
            {
                return true ;
            }
        }
        return false ;
    }
    // 8<---- LDAP AUTHENTICATION PLUGIN --

---[find]---
		case 4:
            $newpass = $this->getRdm(6,"123456789");
			$this->password = "MD5('$newpass')";
            $this->updatePassword();
            break;
---[replace]---
		case 4:
            $newpass = $this->getRdm(6,"123456789");
			$this->password = "MD5('$newpass')";
            $this->updatePassword();
            break;
        // 8<---- LDAP AUTHENTICATION PLUGIN --
        case 5:
             $this->_error['forgot'] = "operation not allowed" ;
             return false ;
             break ;
        // 8<---- LDAP AUTHENTICATION PLUGIN --
