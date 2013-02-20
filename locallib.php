<?php

/**
 * OpenID module/auth local library functions
 *
 * @author Brent Boghosian <brent.boghosian@remote-learner.net>
 * @copyright Copyright (c) 2010,2011 - Remote-Learner
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package openid
 */

// Append the OpenID directory to the include path and include relevant files
set_include_path(get_include_path().PATH_SEPARATOR.$CFG->dirroot.'/auth/openid/lib/openid/');

// Required files (library)
require_once 'Auth/OpenID/Consumer.php';
require_once 'Auth/OpenID/FileStore.php';
require_once 'Auth/OpenID/SReg.php';
require_once 'Auth/OpenID/google_discovery.php'; // BJB110304: For google

define('USE_EMAIL_FOR_USERNAME', 1);   // better than OpenID url if no nickname!

// Added AX (Attribute Exchange) support for Google, Yahoo, etc.
require_once 'Auth/OpenID/AX.php';

define('AX_SCHEMA_NICKNAME','http://axschema.org/namePerson/friendly');
define('AX_SCHEMA_FULLNAME','http://axschema.org/namePerson');
define('AX_SCHEMA_FIRSTNAME','http://axschema.org/namePerson/first');
define('AX_SCHEMA_LASTNAME','http://axschema.org/namePerson/last');
define('AX_SCHEMA_EMAIL','http://axschema.org/contact/email');
define('AX_SCHEMA_COUNTRY','http://axschema.org/contact/country/home');

function get_ax_data( $attr, $ax_obj, $count=0 )
{
    return (empty($ax_obj) || empty($ax_obj->data[$attr]))
           ?  null : $ax_obj->data[$attr][$count];
}

/**
 * Return the hard-coded OpenID Custom login file
 * @uses $CFG
 * @return string  the custom login file
 */
function openid_login_file() {
    global $CFG;
    $themedir = (!empty($CFG->themedir) and file_exists($CFG->themedir) and is_dir($CFG->themedir))
              ? $CFG->themedir : "{$CFG->dirroot}/theme";
    return "{$themedir}/{$CFG->theme}/openid.html"; // TBD
}

/**
 * (originally from lib.php)
 * Normalize an OpenID url for use as a username in the users table
 *
 * The function will ensure the returned username is not present in the
 * database.  It will do this by incrementing an appended number until the
 * username is not found.
 *
 * @param string $openid_url
 * @uses $DB
 * @return string
 */
function openid_normalize_url_as_username($openid_url) {
    global $DB;
    $username = preg_replace('/[^a-z0-9]/i', '', $openid_url);
    $username = substr($username, 0, 90); // Keep it within limits of schema
    $username_tmp = $username;
    $i = 1;

    while ($DB->record_exists('user', array('username' => $username))) {
        $username = $username_tmp.$i++;
    }

    return $username;
}

/**
 * Checks if openid url already exists, outputs error;
 * Attempts to change user account to openid, outputs error on failure.
 * If global $openid_tmp_login is set logs out current temporary user.
 * Called from actions.php
 *
 * @param user object $user - the [potential] user to change to OpenID
 * @param string $url - the unique OpenID URL
 */
function openid_if_unique_change_account($user, $url)
{
    global $openid_tmp_login;

    if (openid_already_exists($url)) {
        $sparam = new stdClass;
        $sparam->url = $url;
        logout_tmpuser_error('auth_openid_url_exists', $sparam);
    } else if (!openid_change_user_account($user, $url, $openid_tmp_login)) {
        logout_tmpuser_error('auth_openid_login_error');
    }
}

/**
 * Call print_error() function, if global $openid_tmp_login set or $force
 * parameter true, function also logs-out current user.
 * Called from actions.php, and this file.
 *
 * @param string $msgkey - the string id to send to print_error()
 *                         from 'auth_openid' module!
 * @param boolean $force - flag to logout user (if true)
 */
function logout_tmpuser_error($msgkey, $param = null, $force = false)
{
    global $USER, $openid_tmp_login;
    if ($force || !empty($openid_tmp_login)) {
        error_log("auth/openid/locallib.php::logout_tmpuser_error({$msgkey}, param, {$force}): reseting temp OpenID login");
        require_logout();
    }
    print_error($msgkey, 'auth_openid', '', $param);
}

/**
 * Get attributes from OpenID response and populate 'user'-like structure
 * If matching user exists then return matching user
 *
 * @param string $resp - the OpenID response
 * @uses $DB
 * @return user object - false on multiple matches, or the matching user object 
 *                       _or_ new user object with members:
 *                           username, email, firstname, lastname, country
 */
function openid_resp_to_user( &$resp )
{
    global $DB;
    $tmp_users = array();
    $user = new stdClass;
    $sreg_resp = Auth_OpenID_SRegResponse::fromSuccessResponse($resp);
    $sreg = $sreg_resp->contents();

    // Add AX support
    $ax_resp = new Auth_OpenID_AX_FetchResponse();
    $ax = $ax_resp->fromSuccessResponse($resp);

    // We'll attempt to use the user's nickname to set their username
    if ( (isset($sreg['nickname']) && !empty($sreg['nickname']) &&
          !($tmp_users['username'] = $DB->get_records('user', array('username' => addslashes($sreg['nickname']))))) ||
         (defined('USE_EMAIL_FOR_USERNAME') && isset($sreg['email']) && !empty($sreg['email'])
          && !($tmp_users['username_email'] = $DB->get_records('user', array('username' => $sreg['email']))))
    ) {
        $user->username = (isset($sreg['nickname']) && !empty($sreg['nickname'])) ? $sreg['nickname'] : $sreg['email'];
    } else
    if ((($nickname = get_ax_data(AX_SCHEMA_NICKNAME, $ax))
           && !($tmp_users['username'] = $DB->get_records('user', array('username' => addslashes($nickname)))))
           || (defined('USE_EMAIL_FOR_USERNAME')
               && ($useremail = get_ax_data(AX_SCHEMA_EMAIL, $ax))
               && !($tmp_users['username_email'] = $DB->get_records('user', array('username' => $useremail)))))
    {   // better to fall-back to email? may show-up in various display blocks
        $user->username = $nickname ? $nickname : $useremail;
    }
    // Otherwise, we'll use their openid url - last resort!
    else {
        $user->username = openid_normalize_url_as_username($resp->identity_url);
    }

    // SREG fullname
    if (isset($sreg['fullname']) && !empty($sreg['fullname'])) {
        $name = openid_parse_full_name($sreg['fullname']);
        $user->firstname = $name['first'];
        $user->lastname = $name['last'];
    } else if (get_ax_data(AX_SCHEMA_LASTNAME, $ax) && get_ax_data(AX_SCHEMA_FIRSTNAME, $ax)) {
        $user->firstname = get_ax_data(AX_SCHEMA_FIRSTNAME, $ax);
        $user->lastname = get_ax_data(AX_SCHEMA_LASTNAME, $ax);
    } else if (get_ax_data(AX_SCHEMA_FULLNAME, $ax)) { // AX fullname
        $name = openid_parse_full_name(get_ax_data(AX_SCHEMA_FULLNAME, $ax));
        $user->firstname = $name['first'];
        $user->lastname = $name['last'];
    }

    if (!empty($user->lastname)) {
        $tmp_users['fullname'] = $DB->get_records('user', array('firstname' => addslashes($user->firstname), 'lastname' => addslashes($user->lastname)));
    }

    // SREG email
    if (!empty($sreg['email']) && !($tmp_users['email'] = $DB->get_records('user', array('email' => $sreg['email'])))) {
        $user->email = $sreg['email'];
    } else if (($useremail = get_ax_data(AX_SCHEMA_EMAIL, $ax))
               && !($tmp_users['email'] = $DB->get_records('user', array('email' => $useremail))) ) {
        $user->email = $useremail;
    }

    // SREG country
    $country = '';
    if (isset($sreg['country']) && !empty($sreg['country'])) {
        $country = $sreg['country'];
    } else if (get_ax_data(AX_SCHEMA_COUNTRY, $ax)) {
        $country = get_ax_data(AX_SCHEMA_COUNTRY, $ax);
    }

    if (!empty($country)) {
        $country_code = strtoupper($country);
        $countries = get_string_manager()->get_list_of_countries();

        if (strlen($country) != 2 || !isset($countries[$country_code])) {
            $countries_keys = array_keys($countries);
            $countries_vals = array_values($countries);
            $country_code = array_search($country, $countries_vals);

            if ($country_code > 0) {
                $country_code = $countries_keys[$country_code];
            } else {
                $country_code = '';
            }
        }

        if (!empty($country_code)) {
            $user->country = $country_code;
        }
    }

  /* We're currently not attempting to get language and timezone values
    // SREG language
    if (isset($sreg['language']) && !empty($sreg['language'])) {
    }

    // SREG timezone
    if (isset($sreg['timezone']) && !empty($sreg['timezone'])) {
    }
  */

    $config = get_config('auth/openid');
    //error_log("/auth/openid/locallib.php::auth/openid::config=...");
    //err_dump($config);

    // Map OpenID fields to whether field MUST be unique
    // TBD: make unique fields configurable im OpenID: auth_config_users.html
    // Keys must match keys in tmp_users[] array - set above.
    $openid_fields = array('email'          => 1, // Email field must be unique
                           'fullname'       => 0, // ok duplicate fullnames
                           'username'       => 0, // ok dup username w/OpenID
                                                  // creates unique username
                           'username_email' => 1  // TBD: No dup username as OpenID email
    );
    foreach($openid_fields as $openid_field => $field_unique) {
        $match_array = str_word_count($config->auth_openid_match_fields, 1, '_');
        $num = !empty($match_array) // && in_array($openid_field, $match_array)
               ? 1 : 0;
        if ($field_unique && !empty($tmp_users[$openid_field]) &&
            count($tmp_users[$openid_field]) > $num)
        {
            //error_log("/auth/openid/locallib.php::openid_resp_to_user() - multiple matches count(tmp_users[{$openid_field}])=".count($tmp_users[$openid_field])." ...");
            //err_dump($tmp_users[$openid_field]);
            //error_log("> match_array=...");
            //err_dump($match_array);
            return false;
        }
    }
    $matching_user = null;
    // check tmp_users[] matches for valid existing user,
    // return false if conflicts between matching fields
    if (!empty($config->auth_openid_match_fields)) {
        $openid_match_fields = explode(',', $config->auth_openid_match_fields);
        foreach ($openid_match_fields as $match_field) {
            $match_field = trim($match_field);
            if (!empty($tmp_users[$match_field]) &&
                count($tmp_users[$match_field]) == 1)
            {
                if (!$matching_user) {
                    $matching_user = reset($tmp_users[$match_field]);
                } else if ($openid_fields[$match_field] &&
                    $matching_user->id != reset($tmp_users[$match_field])->id)
                {   // unique field matches different user!
                    return false;
                }
            }
        }
    }
    if (!empty($matching_user)) {
        merge_user_fields($matching_user, $user);
        //error_log( "openid_resp_to_user() - merged matching user: ");
        //err_dump($matching_user);
        return $matching_user;
    }
    return $user;
}

/**
 * Merge to user objects sub_user into main_user where main_user fields not set
 *
 * @param user object $main_user - the user object to fill-in empty fields.
 * @param user object $sub_user - the user object fields to use where main_user not set.
 * NOTE: currently only checks user fields: username, email, firstname, lastname, country
 */
function merge_user_fields( &$main_user, $sub_user )
{
    $fields = array('username', 'email', 'firstname', 'lastname', 'country');

    foreach ($fields as $user_field) {
        if (empty($main_user->{$user_field}) && !empty($sub_user->{$user_field})){
            $main_user->{$user_field} = $sub_user->{$user_field};
        }
    }
}

/**
 * Function to print 'openid_note_user' string with params
 *
 * @uses $CFG
 */
function print_note_user()
{
    // >= MOODLE 2.0
    global $CFG;
    $a = new stdClass;
    $a->href= "{$CFG->wwwroot}/login/logout.php?sesskey=". sesskey();
    $a->logout = get_string('logout');
    print_string('openid_note_user', 'auth_openid', $a);
}

/**
 * Function to test if USER can login with OpenID
 *
 * @uses $USER
 * @return boolean  true if user can login with OpenID, false otherwise
 */
function user_not_loggedin() {
    global $USER;
    return ($USER->id <= 0 || isguestuser());
}

/**
 * Function to logout guest user
 *
 * @uses $USER
 */
function logout_guestuser() {
    global $USER;
    if (isguestuser()) {
        foreach ($USER as $key => $val) {
            unset($USER->{$key});
        }
        $USER->id = 0;
    }
}

// For debugging - dump object to error_log
function err_dump( $obj )
{
    ob_start();
    var_dump($obj);
    $tmp = ob_get_contents();
    ob_end_clean();
    error_log( $tmp );
}
