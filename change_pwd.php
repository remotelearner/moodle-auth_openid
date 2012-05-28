<?php

/**
 * OpenID Change password form for 'Manage your OpenIDs'
 *
 * @author Brent Boghosian <brent.boghosian@remote-learner.net>
 * @copyright Copyright (c) 2011 Remote-Learner
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package openid
 **/

require_once(dirname(__FILE__) ."/../../config.php");

global $DB, $OUTPUT, $PAGE, $USER;

$context = get_context_instance(CONTEXT_SYSTEM);
$PAGE->set_context($context);
$PAGE->set_url('/auth/openid/change_pwd.php');
$title = get_string('openid_manage', 'auth_openid');
$PAGE->set_title($title);
$PAGE->set_heading(fullname($USER).': '.$title);

echo $OUTPUT->header();
// We don't want to allow use of this script if OpenID auth isn't enabled
if (!is_enabled_auth('openid')) {
    print_error('auth_openid_not_enabled', 'auth_openid');
}

if (!$site = get_site()) {
    print_error('auth_openid_no_site', 'auth_openid');
}
$config = get_config('auth/openid');
include 'user_profile.html';
echo $OUTPUT->footer();

