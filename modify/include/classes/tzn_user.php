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
            //
            // Check if we use LDAP authentication backend. If so, then trying
            // to retrieve the user from the LDAP directory. If found, we auto
            // create it into Taskfreak. Some attributes have to be defined
            // previously into the LDAP directory.
            //
            if (TZN_USER_PASS_MODE == '5' && APK_LDAP_AUTO_USERCREATED)
            {
                $userldap = array() ;
                require_once dirname(__FILE__) . '/apk_ldap.php' ;
                $ldap = new Apk_LdapConnection() ;
                if ($ldap->connect())
                {
                    $filter = $ldap->getFormatedFilter($username) ;
                    $usersdn = $ldap->searchDn($filter) ;
                    if (is_array($usersdn))
                    {
                        $attributes = array('givenname', 'sn', 'mail', 'uid') ;
                        $userldap = $ldap->search($filter, $attributes, $usersdn[0], 'base') ;
                        $userldap = $userldap[0] ;
                    }
                    $ldap->disconnect() ;
                }
                if (sizeof($userldap)>1)
                {
                    $objEditItem = new Member();
                    $objEditItem->initObjectProperties();
                    $userdata['firstName'] = $userldap['givenname'][0] ;
                    $userdata['lastName'] = $userldap['sn'][0] ;
                    $userdata['email'] = $userldap['mail'][0] ;
                    $userdata['username'] = $userldap['uid'][0] ;
                    $userdata['countryId'] = FRK_DEFAULT_COUNTRY ;
                    $objEditItem->setAuto($userdata);
                    $objEditItem->password = $this->getRdm(
                            TZN_USER_PASS_MAX,
                            "123456789abcdefghijklmnopqrstuvwxyz") ;
                    $objEditItem->level = APK_LDAP_AUTO_USERLEVEL ;
                    $objEditItem->enabled = APK_LDAP_AUTO_USERCREATED ? '1' : '0' ;
                    $objEditItem->author->id = 1 ;
                    if ($objEditItem->add()>1)
                    {
                        return $this->login($username,$password,$level);
                    }
                }
            }
            // 8<---- LDAP AUTHENTICATION PLUGIN --

