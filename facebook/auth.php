<?php

/**
 * @author Martin Dougiamas
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 *
 * Authentication Plugin: No Authentication
 *
 * No authentication at all. This method approves everything!
 *
 * 2006-08-31  File created.
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->dirroot.'/auth/facebook/fbsdk/src/facebook.php');
/**
 * Plugin for no authentication.
 */
class auth_plugin_facebook extends auth_plugin_base {

	private $conf;
	private $fb;
	/**
     * Constructor.
     */
    function auth_plugin_facebook() {
        $this->authtype = 'facebook';
        $this->config = get_config('auth/facebook');
		$this->conf = array(
			"appId" =>  $this->config->appid,"secret"=>  $this->config->appsecret
		);
		$this->fb = new Facebook($this->conf);
    }

    /**
     * Returns true if the username and password work or don't exist and false
     * if the user exists and the password is wrong.
     *
     * @param string $username The username
     * @param string $password The password
     * @return bool Authentication success or failure.
     */
    function user_login ($username, $password) {
		return $this->fb->getUser()?true:false;
    }
	
	function get_userinfo($username) {
		$profile = $this->fb->api("/me");
		return $profile;
	}

	
	/**
     * Updates the user's password.
     *
     * called when the user password is updated.
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     * @return boolean result
     *
     */
    function user_update_password($user, $newpassword) {
        $user = get_complete_user_data('id', $user->id);
        return update_internal_user_password($user, $newpassword);
    }

    function prevent_local_passwords() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is 'internal'.
     *
     * @return bool
     */
    function is_internal() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        return null;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param array $page An object containing all the data for this page.
     */
    function config_form($config, $err, $user_fields) {
        include "config.php";
		
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        global $CFG;
		if (!isset ($config->appid)) {
			$config->appid = '';
		}
		if (!isset ($config->appsecret)) {
			$config->appsecret = '';
		}
		if (!isset ($config->createuser)) {
			$config->createuser = 0;
		}else{
			$config->createuser = 1;
		}
		if (!isset ($config->syncuserinfo)) {
			$config->syncuserinfo = 0;
		}else{
			$config->syncuserinfo = 1;
		}
		if (!isset ($config->channelurl)) {
			$config->channelurl = "//".$CFG->wwwroot."/auth/facebook/fblogin.php";
		}
        // save CAS settings
		$plugin = 'auth/facebook';
        set_config('appid', trim($config->appid), $plugin);
        set_config('appsecret', trim($config->appsecret), $plugin);
        set_config('createuser', $config->createuser, $plugin);
        set_config('syncuserinfo', trim($config->syncuserinfo), $plugin);
        set_config('channelurl', $config->channelurl, $plugin);
		return true;
    }
	
	function loginpage_hook() {
		global $CFG, $frm,$user;
		$frm = data_submitted();
		if(!is_object($frm) || !property_exists($frm,'username'))
			include($CFG->dirroot."/auth/facebook/fblogin.php");
		if(is_object($frm) && property_exists($frm,'fblogin') && $frm->fblogin && $this->fb->getUser()){
			$profile = $this->fb->api("/me");
			$email = $profile['email'];
			$u = $this->getMoodleUser($email);
			if($u){
				//If user already has account on moodle and one day he wants to use fb login
				//having same email, the password for user will not be "" and we'll have to
				//supply the user record rather than username/password for enable fb login
				if($u->auth=='facebook'){
					$frm->username = $u->username;
					$frm->password = "";
				}else{
					$user = $u;
				}
			}
			else{
				if($this->config->createuser){
					$usernew = new stdClass();
					$usernew->username = $profile['email'];
					$usernew->password = "";
					$usernew->gender = $profile['gender'];
					$usernew->email = $profile['email'];
					$usernew->auth = "facebook";
					$usernew->firstname = $profile['first_name'];
					$usernew->lastname  = $profile['last_name'];
					$usernew->city = $profile['hometown']['name'];
					$usernew->confirmed = 1;
					$usernew->mnethostid = $CFG->mnet_localhost_id;
					if($this->user_signup($usernew)){
						$frm->username = $profile['email'];
						$frm->password = "";
					}
				}
			}
		}
	}
	
	function user_exists($username){
		global $DB;
		$user = $DB->get_record("user",array("username"=>$username));
		return is_object($user)&property_exists($user, "id")&&  is_numeric($user->id);
	}
	
	
	function user_signup($user, $notify = false) {
		global $CFG, $DB, $PAGE, $OUTPUT;

        require_once($CFG->dirroot.'/user/profile/lib.php');

        if ($this->user_exists($user->username)) {
            print_error('auth_facebook_user_exists', 'auth_facebook');
        }

        $plainslashedpassword = $user->password;
        unset($user->password);

        $user->id = $DB->insert_record('user', $user);
		profile_save_data($user);
        // This will also update the stored hash to the latest algorithm
        // if the existing hash is using an out-of-date algorithm (or the
        // legacy md5 algorithm).
        update_internal_user_password($user, $plainslashedpassword);

        $user = $DB->get_record('user', array('id'=>$user->id));
        events_trigger('user_created', $user);

        
        if ($notify) {
            $emailconfirm = get_string('emailconfirm');
            $PAGE->set_url('/auth/ldap/auth.php');
            $PAGE->navbar->add($emailconfirm);
            $PAGE->set_title($emailconfirm);
            $PAGE->set_heading($emailconfirm);
            echo $OUTPUT->header();
            notice(get_string('emailconfirmsent', '', $user->email), "{$CFG->wwwroot}/index.php");
        } else {
			return true;
		}
	}



	/**
	 * Retrieve the users Moodle ID given a Facebook ID
	 * 
	 * @param int $fb_id Facebook User ID
	 * @return string Moodle User ID
	 */
	function getMoodleUser($fbemail) {
		global $DB;
		return $DB->get_record('user', array('email' => $fbemail), '*');
	}
	
	function prelogout_hook(){
		$this->fb->destroySession();
	}
	
}


