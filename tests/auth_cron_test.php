<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Auth cron objects for component 'auth_openid'
 *
 * @package   auth_openid
 * @author    Linda Vanderbaan <linda.vanderbaan@remote-learner.net>
 * @copyright 2013 Remote Learner  http://www.remote-learner.net/
 * @license   http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

global $CFG;
require_once(__DIR__.'/../auth.php');
require_once(dirname(__FILE__).'/../lib.php');
require_once($CFG->dirroot.'/lib/adminlib.php');

class auth_openid_cron_testcase extends advanced_testcase {
    /**
     * Create a virtual directory structure with $CFG->dataroot.'/openid' as root:
     *
     * @see PHPUnit_Extensions_Database_TestCase::setUp()
     */
    public function setUp() {
        global $CFG;

        // Backup dataroot
        // $this->backupdataroot = $CFG->dataroot;

        // $CFG->dataroot = sys_get_temp_dir();

        $openidroot = $CFG->dataroot.'/openid';
        if (!is_dir($openidroot)) {
            mkdir($openidroot);
        }
        if (!is_dir($openidroot.'/nonces')) {
            mkdir($openidroot.'/nonces');
        }
        // Create association and temp folder so auth plugin is properly setup
        if (!is_dir($openidroot.'/associations')) {
            mkdir($openidroot.'/associations');
        }
        if (!is_dir($openidroot.'/temp')) {
            mkdir($openidroot.'/temp');
        }

        parent::setUp();
    }

    /**
     * Clean up temporary dataroot
     * Restore dataroot
     */
    public function tearDown() {
        global $CFG;

        // Clean up nonce files

        $dir = $CFG->dataroot.'/openid';
        foreach (glob($dir.'/*') as $file) {
            if (is_dir($file)) {
                rmdir($file);
            } else {
                unlink($file);
            }
        }
        rmdir($dir);

        // Restore dataroot
        // set_config('dataroot', $this->backupdataroot);

        parent::tearDown();
    }

    /**
     * Create nonce files
     *
     * @param today integer Timestamp for current time
     * @param yesterday integer Timestamp for 1 day ago
     * @param lastweek integer Timestamp for 1 week ago
     */
    public function create_nonce_files($today, $yesterday, $lastweek) {
        global $CFG;

        $filepath = $CFG->dataroot.'/openid/nonces/';
        $todayfile = $filepath.$today.'-file.tst';
        $yesterdayfile = $filepath.$yesterday.'-file.tst';
        $lastweekfile = $filepath.$lastweek.'-file.tst';

        // Add timestamped files
        touch($todayfile);
        chmod($todayfile, 0777);
        touch($yesterdayfile);
        chmod($yesterdayfile, 0777);
        touch($lastweekfile);
        chmod($lastweekfile, 0777);
    }

    /**
     * Clean up nonce folder and files
     */
    public function cleanup_nonce_folder() {
        global $CFG;

        $files = glob($CFG->dataroot.'/openid/nonces/*'); // get all file names
        foreach ($files as $file) { // iterate files
            if (is_file($file)) {
                unlink($file); // delete file
            }
        }
    }

    /**
     * Data provider that provides timestamp values
     *
     * @return array The appropriate parameter data
     */
    public function time_provider() {
        $now = time();
        return array(
            array($now, '', 'first'),
            array($now, strtotime('-2 hours', $now), 'sameday'),
            array($now, strtotime('-26 hours', $now), 'nextday')
        );
    }

    /**
     * Test very first time the cron is run for the nonce cleanup
     * @param integer $now The current time
     * @param integer $timestamp The calculated timestamp
     * @param string $testtime When the test is being run
     * @dataProvider time_provider
     * @group auth_openid
     */
    public function test_cron_run($now, $timestamp, $testtime) {
        global $CFG;
        $this->resetAfterTest(true);

        // Initialize the timestamp
        set_config('lastcleanup', $timestamp, 'auth/openid');
        $yesterday = strtotime('-1 day -5 minutes', $now);
        $lastweek = strtotime('-1 week', $now);
        // Convert timestamps to base 16
        $today = base_convert($now, 10, 16);
        $yesterday = base_convert($yesterday, 10, 16);
        $lastweek = base_convert($lastweek, 10, 16);

        // Create nonce files
        $this->create_nonce_files($today, $yesterday, $lastweek);

        // Run the cron
        $openid = new auth_plugin_openid();
        $openid->cron();

        // Validate that the files left are the expected files
        $this->assertFileExists($CFG->dataroot.'/openid/nonces/'.$today.'-file.tst');
        if ($testtime == 'sameday') {
            $this->assertFileExists($CFG->dataroot.'/openid/nonces/'.$yesterday.'-file.tst');
            $this->assertFileExists($CFG->dataroot.'/openid/nonces/'.$lastweek.'-file.tst');
        } else {
            $this->assertFileNotExists($CFG->dataroot.'/openid/nonces/'.$yesterday.'-file.tst');
            $this->assertFileNotExists($CFG->dataroot.'/openid/nonces/'.$lastweek.'-file.tst');
        }

        // Clean up nonce files
        $this->cleanup_nonce_folder();
    }
}
