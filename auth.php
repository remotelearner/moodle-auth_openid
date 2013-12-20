<?php

/**
 * Authentication Plugin: OpenID Authentication
 *
 * This plugin provides standard OpenID consumer functionality in Moodle.
 *
 * @author Brent Boghosian <brent.boghoosian@remote-learner.net>
 * @copyright Copyright (c) 2011 Remote-Learner
 * @author Stuart Metcalfe <info@pdl.uk.com>
 * @copyright Copyright (c) 2007 Canonical
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once $CFG->libdir.'/authlib.php';
require_once $CFG->dirroot.'/auth/openid/lib.php';

// Append the OpenID directory to the include path and include relevant files
set_include_path(get_include_path().PATH_SEPARATOR.$CFG->dirroot.'/auth/openid/lib/openid/');

// Required files (library)
require_once $CFG->dirroot.'/auth/openid/locallib.php';

define('GOOGLE_OPENID_URL', 'https://www.google.com/accounts/o8/id');

// Include the custom event script if it exists
if (file_exists($CFG->dirroot.'/auth/openid/event.php')) {
    include $CFG->dirroot.'/auth/openid/event.php';
}

/**
 * OpenID authentication plugin.
 */
class auth_plugin_openid extends auth_plugin_base {

    /**
     * Class constructor
     *
     * Assigns default config values and checks for requested actions
     */
    function auth_plugin_openid() {
        $this->authtype     = 'openid';
        $this->pluginconfig = 'auth/'.$this->authtype;
        $this->roleauth     = 'auth_'.$this->authtype;
        $this->errorlogtag  = '['.strtoupper($this->roleauth).'] ';
        $this->config       = get_config($this->pluginconfig);

        // Set some defaults if not already set up
        if (!isset($this->config->openid_sreg_required)) {
            set_config('openid_sreg_required', 'nickname,email,fullname,country', 'auth/openid');
            $this->config->openid_sreg_required='nickname,email,fullname,country';
        }

        if (!isset($this->config->openid_sreg_optional)) {
            set_config('openid_sreg_optional', '', 'auth/openid');
            $this->config->openid_sreg_optional='';
        }

        if (!isset($this->config->openid_privacy_url)) {
            set_config('openid_privacy_url', '', 'auth/openid');
            $this->config->openid_privacy_url='';
        }
        
        if (!isset($this->config->openid_non_whitelisted_status)) {
            set_config('openid_non_whitelisted_status', 0, 'auth/openid');
            $this->config->openid_non_whitelisted_status=0;
        }
        
        if (!isset($this->config->auth_openid_allow_account_change)) {
            set_config('auth_openid_allow_account_change', 'false', 'auth/openid');
            $this->config->auth_openid_allow_account_change='false'; // TBD: was true
        }
        
        if (!isset($this->config->auth_openid_allow_multiple)) {
            set_config('auth_openid_allow_multiple', 'true', 'auth/openid');
            $this->config->auth_openid_allow_multiple='true';
        }

        if (!isset($this->config->auth_openid_limit_login)) {
            set_config('auth_openid_limit_login', 'false', 'auth/openid');
            $this->config->auth_openid_limit_login='false';
        }

        if (!isset($this->config->auth_openid_custom_login)) {
            set_config('auth_openid_custom_login', '', 'auth/openid');
            $this->config->auth_openid_custom_login='';
        }

        if (!isset($this->config->auth_openid_google_apps_domain)) {
            set_config('auth_openid_google_apps_domain', '', 'auth/openid');
            $this->config->auth_openid_google_apps_domain = '';
        }

        if (!isset($this->config->auth_openid_confirm_switch)) {
            set_config('auth_openid_confirm_switch', 'true', 'auth/openid');
            $this->config->auth_openid_confirm_switch='true';
        }

        if (!isset($this->config->auth_openid_email_on_change)) {
            set_config('auth_openid_email_on_change', 'true', 'auth/openid');
            $this->config->auth_openid_email_on_change='true';
        }

        if (!isset($this->config->auth_openid_create_account)) {
            set_config('auth_openid_create_account', 'true', 'auth/openid');
            $this->config->auth_openid_create_account='true';
        }

        if (!isset($this->config->auth_openid_match_fields)) {
            set_config('auth_openid_match_fields', 'email', 'auth/openid');
            $this->config->auth_openid_match_fields='email';
        }

        if (!isset($this->config->auth_openid_clear_wantsurl)) {
            set_config('auth_openid_clear_wantsurl', '', 'auth/openid');
            $this->config->auth_openid_clear_wantsurl = '';
        }

        // Define constants used in OpenID lib
        if (!defined('OPENID_USE_IDENTIFIER_SELECT')) { // BJB101123: fix redefined error
            define('OPENID_USE_IDENTIFIER_SELECT', 'false');
        }
    }
    
    /**
     * Returns true if this authentication plugin can change the users'
     * password.
     *
     * Cheeky hack to place OpenID configuration in the user's main profile
     * page.
     *
     * Takes advantage of the fact that /user/view.php checks the user's
     * authentication class (ie: this one!) to see if it offers the ability
     * to change passwords.  This plugin can't change passwords so we return
     * false but we also use it as the hook to display the form.
     *
     * @uses $DB
     * @uses $USER
     * @return bool
     */
    function can_change_password() {
        global $DB, $USER;
        return(is_enabled_auth('openid') && !empty($USER) && $USER->id > 0 &&
               property_exists($USER, 'auth') && $USER->auth == 'openid' &&
               ($this->config->auth_openid_allow_multiple == 'true' ||
                $DB->count_records('openid_urls', array('userid' => $USER->id))
                > 1)
        );
    }

    /**
     * Returns the URL for changing the users' passwords: 'Manage your OpenIDs'
     * URL can be used.
     *
     * This method is used if can_change_password() returns true.
     * This method is called only when user is logged in, it may use global $USER.
     *
     * @uses $CFG
     * @return [moodle_url] url of the 'change password' page
     */
    function change_password_url() {
        global $CFG;
        return $CFG->wwwroot.'/auth/openid/change_pwd.php';
    }

    /**
     * Returns true if plugin allows confirming of new users.
     *
     * @return bool
     */
    function can_confirm() {
        return true;
    }

    /**
     * Confirm the new user as registered.
     *
     * @param string $username (with system magic quotes)
     * @param string $confirmsecret (with system magic quotes)
     * @uses $DB
     */
    function user_confirm($username, $confirmsecret) {
        global $DB;
        $user = get_complete_user_data('username', $username);

        if (!empty($user)) {
            if ($user->confirmed) {
                return AUTH_CONFIRM_ALREADY;

            } else if ($user->auth != $this->authtype) {
                return AUTH_CONFIRM_ERROR;

            } else if ($user->secret == stripslashes($confirmsecret)) {   // They have provided the secret key to get in
                if (!$DB->set_field('user', 'confirmed', 1, array('id' => $user->id))) {
                    return AUTH_CONFIRM_FAIL;
                }
                if (!$DB->set_field('user', 'firstaccess', time(), array('id' => $user->id))) {
                    return AUTH_CONFIRM_FAIL;
                }
                return AUTH_CONFIRM_OK;
            }
        } else {
            return AUTH_CONFIRM_ERROR;
        }
    }

    /**
     * Delete user openid records from database
     *
     * @param object $user       Userobject before delete    (without system magic quotes)
     * @uses $DB
     */
    function user_delete($olduser) {
        global $DB;
        $DB->delete_records('openid_urls', array('userid' => $olduser->id));
    }

    /**
     * This is the primary method that is used by the authenticate_user_login()
     * function in moodlelib.php. This method should return a boolean indicating
     * whether or not the username and password authenticate successfully.
     *
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     *
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        // This plugin doesn't use usernames and passwords
        return false;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     */
    function config_form($config, $err, $user_fields) {
        global $CFG, $USER;
        include $CFG->dirroot.'/auth/openid/auth_config.html';
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     * @param object object with submitted configuration settings (without system magic quotes)
     * @param array $err array of error messages
     */
    function validate_form($form, &$err) {
        //override if needed
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     *
     * @param object object with submitted configuration settings (without system magic quotes)
     * @uses $DB
     */
    function process_config($config) {
        global $DB;
        $page = optional_param('page', '', PARAM_ALPHA);
        
        if ($page == 'users') {
            $vars = array(
                'auth_openid_allow_account_change',
                'auth_openid_allow_multiple',
                'openid_non_whitelisted_status',
                'auth_openid_create_account',
                'auth_openid_limit_login',
                'auth_openid_custom_login',
                'auth_openid_google_apps_domain',
                'auth_openid_confirm_switch',
                'auth_openid_email_on_change',
                'auth_openid_match_fields',
                'auth_openid_clear_wantsurl'
            );
        } elseif ($page == 'sreg') {
            $vars = array(
                'openid_sreg_required',
                'openid_sreg_optional',
                'openid_privacy_url'
            );
        } elseif ($page == 'servers') {
            $vars = array();
            $add = optional_param('add_server', null, PARAM_RAW);
            
            if ($add != null) {
                $record = new object();
                $record->server = required_param('openid_add_server', PARAM_RAW);
                $record->listtype = optional_param('openid_add_listtype', 0, PARAM_INT);
                
                if ($record->listtype != OPENID_WHITELIST && $record->listtype != OPENID_BLACKLIST) {
                    $record->listtype = OPENID_GREYLIST;
                }
                
                if (!empty($record->server) && !$DB->record_exists('openid_servers', array('server' => $record->server))) {
                    $DB->insert_record('openid_servers', $record);
                }
            } else {
                $servers = optional_param_array('servers', array(), PARAM_RAW);
                
                foreach ($servers as $id=>$val) {
                    $id = intval($id);
                    $val = intval($val);
                    
                    if ($id < 1) {
                        continue;
                    }
                    
                    // If we encounter a 'delete' request
                    if ($val < 0) { 
                        $DB->delete_records('openid_servers', array('id' => $id));
                        continue;
                    }
                    
                    // Otherwise, force a valid value (default 'GREYLIST')
                    if ($val != OPENID_WHITELIST && $val != OPENID_BLACKLIST) {
                        $val = OPENID_GREYLIST;
                    }
                    
                    // And update record
                    $record = new stdClass;
                    $record->id = $id;
                    $record->listtype = $val;
                    $DB->update_record('openid_servers', $record);
                }
            }
        }
        
        foreach ($vars as $var) {
            set_config($var, isset($config->$var) ? $config->$var : '', 'auth/openid');
            $this->config->$var = isset($config->$var) ? $config->$var : '';
        }
        
        return false;
    }

    /**
     * New method for OpenID SSO operation using custom login config setting
     * for OpenID_SSO url if no a relative path but a url
     *
     * @return boolean - true if OpenID SSO operation is configured,
     *                   false otherwise.
     */
    function is_sso() {
        return(!empty($this->config->auth_openid_limit_login) &&
               !empty($this->config->auth_openid_custom_login) &&
               strpos($this->config->auth_openid_custom_login, 'http') === 0);
    }

    /**
     * Hook for overriding behavior of login page.
     * This method is called from login/index.php page for all enabled auth
     * plugins.
     *
     * We're overriding the default login behaviour when login is attempted or
     * an OpenID response is received.  We also provide our own login form if
     * an alternate login url hasn't already been defined.  This doesn't alter
     * the site's configuration value.
     * @uses $CFG
     * @uses $DB
     * @uses $frm - from login page
     * @uses $user - from login page
     */
    function loginpage_hook() {
        global $CFG, $DB;
        global $frm, $user; // Login page variables

        $username = optional_param('username', null, PARAM_ALPHANUM);
        $password = optional_param('password', null, PARAM_ALPHANUM);
        $admin = optional_param('admin', null, PARAM_ALPHANUM);
        $openid_url = optional_param('openid_url', null, PARAM_RAW);
        $google_apps_domain = optional_param('googleapps_domain',
                                  $this->config->auth_openid_google_apps_domain,
                                  PARAM_RAW);
        $mode = optional_param('openid_mode', null, PARAM_ALPHANUMEXT);
        $allow_append = ($this->config->auth_openid_allow_multiple=='true');
        $referer = get_referer(false);
        // Check for OpenID login override 'admin=true'
        if ($admin === null && strstr($referer,'admin=true')) {
            $admin = 'true';
        }
        if (!empty($admin) && $admin == 'true') {
            return;
        }

        // We need to use our OpenID login form
        if (empty($CFG->alternateloginurl)) {
            $CFG->alternateloginurl = $CFG->wwwroot.'/auth/openid/login.php';
        }
        
        // No response received, form submitted OpenID URL or GoogleApps domain is set and "OpenID authentication only" option is set.
        if ($mode == null && ($openid_url != null || (!empty($google_apps_domain) && !empty($this->config->auth_openid_limit_login)))
            && ($username == null && $password == null)) {
            // If we haven't received a response, then initiate a request
            $this->do_request();
        } elseif ($mode != null) {
            // If openid.mode is set then we'll assume this is a response
            $resp = $this->process_response();
            
            if ($resp !== false) {
                global $SESSION;
                if (!empty($this->config->auth_openid_clear_wantsurl) &&
                    !empty($SESSION->wantsurl)) {
                    unset($SESSION->wantsurl);
                }

                $url = $resp->identity_url;
                $server = $resp->endpoint->server_url;
                
                if (!openid_server_allowed($server, $this->config)) {
                    $sparam = new stdClass;
                    $sparam->url = $server;
                    print_error('auth_openid_server_blacklisted',
                                'auth_openid', '', $sparam);
                }
                logout_guestuser();
                if (openid_urls_table(OPENID_URLS_EXIST, $url)) {
                    // Get the user associated with the OpenID
                    $userid = openid_urls_table(OPENID_URLS_GET, $url, 'userid');
                    $user = get_complete_user_data('id', $userid);
                    
                    // If the user isn't found then there's a database
                    // discrepancy.  We delete this entry and create a new user
                    if (!$user) {
                        openid_urls_table(OPENID_URLS_DELETE, $url);
                        $user = $this->_open_account($resp);
                    }
                    
                    // Otherwise, the user is found and we call the optional
                    // on_openid_login function
                    elseif (function_exists('on_openid_login')) {
                        on_openid_login($resp, $user);
                    }
                } else {
                    // Otherwise, create a new account
                    $user = $this->_open_account($resp,
                                 !isset($this->config->auth_openid_create_account)
                                 || $this->config->auth_openid_create_account == 'true');
                }
                if (!empty($user)) {
                    $frm = new stdClass();
                    $frm->username = $user->username;
                    $frm->password = $user->password;
                }
            }
        }
    }
    
    /**
     * Initiate an OpenID request
     *
     * @param boolean $allow_sreg Default true
     * @param string $process_url Default empty (will use $CFG->wwwroot)
     * @param array $params Array of extra parameters to append to the request
     * @uses $CFG
     * @uses $USER
     * @uses $OUTPUT
     */
    function do_request($allow_sreg=true, $process_url='', $params=array()) {
        global $CFG, $USER, $OUTPUT;

        // Create the consumer instance
        $store = new Auth_OpenID_FileStore($CFG->dataroot.'/openid');
        $consumer = new Auth_OpenID_Consumer($store);
        $openid_url = optional_param('openid_url', null, PARAM_RAW);
        $google_apps_domain = optional_param('googleapps_domain',
                                  $this->config->auth_openid_google_apps_domain,
                                  PARAM_RAW);
        if (defined('GOOGLE_OPENID_URL') && !empty($openid_url) &&
            (stristr($openid_url,'@google.') || stristr($openid_url,'@gmail.')))
        {
            // BJB101206: map Google email addresses to OpenID url
            $tmpemail = $openid_url;
            $openid_url = GOOGLE_OPENID_URL;
            logout_guestuser();
            if (empty($USER->id) &&
               ($tmpuser = get_complete_user_data('email', $tmpemail)) &&
                $tmpuser->auth != 'openid')
            {
                $allow_sreg = true; // would like to verify email later
                $process_url = $CFG->wwwroot.'/auth/openid/actions.php';
                $USER = $tmpuser;
                $params['openid_tmp_login'] = true; // require flag in action.php
                $params['openid_action'] = 'change';
                $params['openid_url'] = $openid_url;
                $params['openid_mode'] = 'switch2openid'; // arbitrary != null
                //error_log('/auth/openid/auth.php::do_request() - Found user email: '.$tmpemail);
            }
        }

        if (!empty($google_apps_domain)) {
            $_SESSION['openid_googleapps_domain'] = $openid_url = $google_apps_domain;
            new GApps_OpenID_Discovery($consumer);
        }
        $authreq = $consumer->begin($openid_url);

        if (!$authreq && $this->is_sso()) {
            $endpoint = new Auth_OpenID_ServiceEndpoint();
            $endpoint->server_url = $openid_url;
            $endpoint->claimed_id = Auth_OpenID_IDENTIFIER_SELECT;
            $endpoint->type_uris = array('http://specs.openid.net/auth/2.0/signon');
            $authreq = $consumer->beginWithoutDiscovery($endpoint);
        }

        if (!$authreq) {
            print_error('auth_openid_login_error', 'auth_openid');
        } else {
            // Add any simple registration fields to the request
            if ($allow_sreg === true) {
                $sreg_added = false;
                $req = array();
                $opt = array();
                $privacy_url = null;
                
                // Required fields
                if (!empty($this->config->openid_sreg_required)) {
                    $req = array_map('trim', explode(',', $this->config->openid_sreg_required));
                    $sreg_added = true;
                }
                
                // Optional fields
                if (!empty($this->config->openid_sreg_optional)) {
                    $opt = array_map('trim', explode(',', $this->config->openid_sreg_optional));
                    $sreg_added = true;
                }
                
                // Privacy statement
                if ($sreg_added && !empty($this->config->openid_privacy_url)) {
                    $privacy_url = $this->config->openid_privacy_url;
                }
                
                // We call the on_openid_do_request event handler function if it
                // exists. This is called before the simple registration (sreg)
                // extension is added to allow changes to be made to the sreg
                // data fields if required
                if (function_exists('on_openid_do_request')) {
                    on_openid_do_request($authreq);
                }
                
                // Finally, the simple registration data is added
                if ($sreg_added && !(sizeof($req)<1 && sizeof($opt)<1)) {

                    $sreg_request = Auth_OpenID_SRegRequest::build(
                        $req, $opt, $privacy_url);

                    if ($sreg_request) {
                        $authreq->addExtension($sreg_request);
                    }
                }

                // Add AX (Attribute Exchange) support
                $AXattr = array();
                $AXattr[] = Auth_OpenID_AX_AttrInfo::make(AX_SCHEMA_EMAIL,1,1, 'email');
                $AXattr[] = Auth_OpenID_AX_AttrInfo::make(AX_SCHEMA_NICKNAME,1,1, 'nickname');
                $AXattr[] = Auth_OpenID_AX_AttrInfo::make(AX_SCHEMA_FULLNAME,1,1, 'fullname');
                $AXattr[] = Auth_OpenID_AX_AttrInfo::make(AX_SCHEMA_FIRSTNAME,1,1, 'firstname');
                $AXattr[] = Auth_OpenID_AX_AttrInfo::make(AX_SCHEMA_LASTNAME,1,1, 'lastname');
                $AXattr[] = Auth_OpenID_AX_AttrInfo::make(AX_SCHEMA_COUNTRY,1,1, 'country');
                // Create AX fetch request
                $ax = new Auth_OpenID_AX_FetchRequest();

                // Add attributes to AX fetch request
                foreach($AXattr as $attr){
                    $ax->add($attr);
                }

                // Add AX fetch request to authentication request
                $authreq->addExtension($ax);
            }

            // Prepare the remaining components for the request
            if (empty($process_url)) {
                $process_url = $CFG->wwwroot.'/login/index.php';
            }
            
            if (is_array($params) && !empty($params)) {
                $query = '';
                
                foreach ($params as $key=>$val) {
                    $query .= '&'.$key.'='.$val;
                }
                
                $process_url .= '?'.substr($query, 1);
            }
            
            $trust_root = $CFG->wwwroot.'/';
            $_SESSION['openid_process_url'] = $process_url;
            
            // Finally, redirect to the OpenID provider
            // Check if the server is allowed ...
            if (!openid_server_allowed($authreq->endpoint->server_url, $this->config)) {
                $sparam = new stdClass;
                $sparam->url = $authreq->endpoint->server_url;
                print_error('auth_openid_server_blacklisted',
                            'auth_openid', '', $sparam);
            }
            
            // If this is an OpenID 1.x request, redirect the user
            elseif ($authreq->shouldSendRedirect()) {
                $redirect_url = $authreq->redirectURL($trust_root, $process_url);

                // If the redirect URL can't be built, display an error message.
                if (Auth_OpenID::isFailure($redirect_url)) {
                    echo $OUTPUT->error_text($redirect_url->message);
                    exit; // TBD
                }

                // Otherwise, we want to redirect
                else {
                    redirect($redirect_url);
                }
            }

            // or use the post form method if using OpenID 2.0
            else {
                // Generate form markup and render it.
                $form_id = 'openid_message';
                $message = $authreq->getMessage($trust_root, $process_url, false);
                
                // Display an error if the form markup couldn't be generated;
                // otherwise, render the HTML.
                if (Auth_OpenID::isFailure($message)) {
                    echo $OUTPUT->error_text($message);
                    exit; // TBD
                }
                
                else {
                    $form_html = $message->toFormMarkup($authreq->endpoint->server_url,
                        array('id' => $form_id), get_string('continue'));
                    echo '<html><head><title>OpenID request</title></head><body onload="document.getElementById(\'',$form_id,'\').submit();" style="text-align: center;"><div style="background: lightyellow; border: 1px solid black; margin: 30px 20%; padding: 5px 15px;"><p>',get_string('openid_redirecting', 'auth_openid'),'</p></div>',$form_html,'</body></html>';
                    exit;
                }
            }
        }
    }
    
    /**
     * Process an OpenID response
     *
     * By default, this method uses the print_error() function to display errors
     * ... if you want to display errors inline using the notify() function
     * you will need to pass true to the $notify_errors argument.
     *
     * @param boolean $notify_errors Default false
     * @return mixed Successful response object or false
     */
    function process_response($notify_errors=false) {
        global $CFG;

        // Create the consumer instance
        $store = new Auth_OpenID_FileStore($CFG->dataroot.'/openid');
        $consumer = new Auth_OpenID_Consumer($store);
        if (!empty($_SESSION['openid_googleapps_domain'])) {
            unset($_SESSION['openid_googleapps_domain']);
            new GApps_OpenID_Discovery($consumer);
        }
        $resp = $consumer->complete($_SESSION['openid_process_url']);
        unset($_SESSION['openid_process_url']);

        // Act based on response status
        switch ($resp->status) {
        case Auth_OpenID_SUCCESS:
            // Auth succeeded
            return $resp;

        case Auth_OpenID_CANCEL:
            // Auth cancelled by user.
            if ($notify_errors) {
                notify(get_string('auth_openid_user_cancelled', 'auth_openid'));
            } else {
                print_error('auth_openid_user_cancelled', 'auth_openid');
            }
            break;

        case Auth_OpenID_FAILURE:
            // Auth failed for some reason
            $sparam = new stdClass;
            $sparam->str = openid_get_friendly_message($resp->message);
            error_log("/auth/openid/auth.php::process_response() - Auth_OpenID_FAILURE: {$sparam->str}");
            if ($notify_errors) {
                notify(get_string('auth_openid_login_failed', 'auth_openid',
                                  $sparam));
            } else {
                print_error('auth_openid_login_failed', 'auth_openid', '',
                            $sparam);
            }
        }

        return false;
    }
    
    /**
     * Open user account using SREG & AX data if available
     * If no matching user found and create flag is true, creates new user account
     *
     * @access private
     * @param object &$resp An OpenID consumer response object
     * @param boolean $create_flag - set if account creation permitted, default: true
     * @uses $CFG
     * @uses $DB
     * @uses $USER
     * @uses $openid_tmp_login
     * @return object The new user
     */
    function _open_account(&$resp, $create_flag = true) {
        global $CFG, $DB, $USER, $openid_tmp_login;

        $url = $resp->identity_url;
        $password = hash_internal_user_password('openid');
        $server = $resp->endpoint->server_url;

        $user = openid_resp_to_user($resp);
        if ($user == false) { // multiple matches to users! Don't know which user to pick.
            print_error('auth_openid_multiple_matches', 'auth_openid');
            return false; // won't get here.
        }

        if (isset($user->id)) {
            $openid_tmp_login = true;
            $openid_action = 'change';
            if ($user->auth == 'openid') {
                if (empty($this->config->auth_openid_allow_multiple)) {
                    print_error('auth_openid_no_multiple', 'auth_openid');
                    return false;
                }
                $openid_action = 'append';
            } else if (empty($this->config->auth_openid_confirm_switch)) {
                openid_if_unique_change_account($user, $url);
                return $USER;
            }
            $USER = clone($user); // To clone or not to clone
            redirect("{$CFG->wwwroot}/auth/openid/actions.php?openid_tmp_login=1&openid_action={$openid_action}&openid_url={$url}");
            // Try to get it not to make second request to be accepted, double confirm - TBD: openid_mode=switch2openid ???
        }

        if (!$create_flag) {
            // Error: This site is configured to disallow new users via OpenID
            print_error('auth_openid_require_account', 'auth_openid');
            return false; // won't get here.
        }

        $usertmp = create_user_record($user->username, $password, 'openid');
        $user->id = $usertmp->id;
        openid_append_url($user, $url);

        if (!isset($user->city) || $user->city == '') {
            //use "*" as the default city name
            $user->city = '*';
        }
        if (empty($user->country) && !empty($CFG->country)) {
            //use the configured default country code
            $user->country = $CFG->country;
        }
        if (empty($user->country)) {
            //out of other options, to try to copy the admin's country
            if ($admin = get_admin()) {
                $user->country = $admin->country;
            }
        }

        $DB->update_record('user', $user);
        $user = get_complete_user_data('id', $user->id);

        events_trigger('user_created', $user); // Port ELIS-4347

        if (function_exists('on_openid_create_account')) {
            on_openid_create_account($resp, $user);
        }

        // Redirect the user to their profile page if not set up properly
        $redirect = !empty($user) && (user_not_fully_set_up($user) || empty($user->country));
        if ($redirect) {
            $USER = clone($user);
            $urltogo = $CFG->wwwroot.'/user/edit.php';
            redirect($urltogo);
        }

        if (openid_server_requires_confirm($server, $this->config)) {
            $secret = random_string(15);
            $DB->set_field('user', 'secret', $secret, array('id' => $user->id));
            $user->secret = $secret;
            $DB->set_field('user', 'confirmed', 0, array('id' => $user->id));
            $user->confirmed = 0;
            openid_send_confirmation_email($user);
        }

        return $user;
    }

    function compare_useremail_response($user, $response, &$return_email = null)
    {
        $email = null;
        if (empty($user) || empty($user->email))
            return true; // cannot compare, assume ok

        $sreg_resp = Auth_OpenID_SRegResponse::fromSuccessResponse($response);
        $sreg = $sreg_resp->contents();

        // Add AX (Attributes Exchange) support
        $ax_resp = new Auth_OpenID_AX_FetchResponse();
        $ax = $ax_resp->fromSuccessResponse($response);
        $email = get_ax_data(AX_SCHEMA_EMAIL, $ax);

        if (empty($email) && !empty($sreg['email']))
            $email = $sreg['email'];

        if ($return_email !== null)
            $return_email = $email;
        //error_log("/auth/openid/auth.php::compare_useremail_response(): $user->email ?= $email ");
        return( !empty($email) ? ($user->email == $email) : true);
    }

    /**
     * Cron function will be called automatically by cron.php every 5 minutes
     */
    function cron() {
        global $CFG;

        $current = time();

        // Get previous run timestamp
        $previous = get_config('auth/openid', 'lastcleanup');
        $interval = $current - $previous;
        $intervaldays = floor($interval/(60*60*24));

        // Nonce cleanup should be run once per day
        // No assocations are created, and thus do not need to be cleaned up
        if ($intervaldays >= 1) {
            // Create the consumer instance
            $store = new Auth_OpenID_FileStore($CFG->dataroot.'/openid');
            $store->cleanupNonces();
            set_config('lastcleanup', $current, 'auth/openid');
            $this->config->lastcleanup = $current;
        }
    }
}
