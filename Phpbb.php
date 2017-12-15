<?php if (!defined('BASEPATH')) exit('No direct script access allowed');

/**
* CodeIgniter phpBB3 Library
*
* CodeIgniter phpBB3 bridge (access phpBB3 user sessions and other functions inside your CodeIgniter applications).
*
* @author Tomaž Muraus
* @modified Mehul V(mehulvadodariya2012@gmail.com)
* @version    2.0 
*/
class Phpbb
{
    public $CI;
    protected $_user;

    /**
     * Constructor.
     */
    public function __construct()
    {
        if (!isset($this->CI))
        {
            $this->CI =& get_instance();
        }
    }
    /*
     * 
     * Create session without password. 
     * @param mixed $userId valid phpbb userid.
     * @return array User information
     */
    public function loginUserWithoutPassword($userId){
        global $phpbb_dispatcher,$phpbb_root_path, $phpEx, $user, $auth, $cache, $db, $config, $template, $table_prefix,$phpbb_container;

        defined('IN_PHPBB') or define('IN_PHPBB', TRUE);
        defined('FORUM_ROOT_PATH') or define('FORUM_ROOT_PATH', './forum/');
        
        $phpbb_root_path = (defined('PHPBB_ROOT_PATH')) ? PHPBB_ROOT_PATH : FORUM_ROOT_PATH;
        $phpEx = substr(strrchr(__FILE__, '.'), 1);

        // Include needed files
        require_once FORUM_ROOT_PATH.'common.' . $phpEx;
        
        defined('IN_LOGIN') or define('IN_LOGIN', true);
        
        // Initialize phpBB user session
        $user->session_kill(false);
        $user->session_begin();
        $user->session_create($userId);
        $this->_user = $user;
        
        return $user->data;
        
        
    }
    /*
     * Create login session in PHPbb
     * @param String $username valid username
     * @param String $password valid password
     * @param Boolean $autologin remember
     */
    public function loginUser($username,$password,$autologin){
        
        
        // Set the variables scope
        global $phpbb_dispatcher,$phpbb_root_path, $phpEx, $user, $auth, $cache, $db, $config, $template, $table_prefix,$phpbb_container;

        defined('IN_PHPBB') or define('IN_PHPBB', TRUE);
        defined('FORUM_ROOT_PATH') or define('FORUM_ROOT_PATH', './forum/');
        
        $phpbb_root_path = (defined('PHPBB_ROOT_PATH')) ? PHPBB_ROOT_PATH : FORUM_ROOT_PATH;
        $phpEx = substr(strrchr(__FILE__, '.'), 1);

        // Include needed files
        require_once FORUM_ROOT_PATH.'common.' . $phpEx;
        
        defined('IN_LOGIN') or define('IN_LOGIN', true);
        
        // Initialize phpBB user session
        $user->session_begin();
        $auth->acl($user->data);
        $user->setup();
        $result = $auth->login($username,$password,$autologin,1,0);
         
        // Save user data into $_user variable
        $this->_user = $user;
        
        return $result;
    }
    /*
     * Logout user login session
     * @param String $sid sesstion string (session_id)
     * @param int $uid valid user id
     * @return Array Anonymous user
     */
    public function logoutUser($sid,$uid){
        // Set the variables scope
        global $phpbb_dispatcher,$phpbb_root_path, $phpEx, $user, $auth, $cache, $db, $config, $template, $table_prefix,$phpbb_container;

        defined('IN_PHPBB') or define('IN_PHPBB', TRUE);
        defined('FORUM_ROOT_PATH') or define('FORUM_ROOT_PATH', './forum/');
        $phpbb_root_path = (defined('PHPBB_ROOT_PATH')) ? PHPBB_ROOT_PATH : FORUM_ROOT_PATH;
        $phpEx = substr(strrchr(__FILE__, '.'), 1);

        // Include needed files
        require_once FORUM_ROOT_PATH.'common.' . $phpEx;
        
        define('IN_LOGIN', true);
        
        // Initialize phpBB user session
        $user->session_id = $sid;
        $user->data['user_id'] = $uid;
        $user->session_kill();
        $user->session_begin();
        
        return $user->data;
    }
    /*
     * 
     * Register user to PHPbb
     * @param String $username User username 
     * @param String $password Users password
     * @param String $email user email address
     * @param IP $ip user current ip address
     */
    public function registerUser($username,$password,$email,$ip){
        
        define('IN_PHPBB', true);

        $user_regdate = time();
        $username = $username;
        $password = $this->phpbb_hash($password);
        $email = $email;
         

        $username_clean = strtolower($username);
        $user_email_hash = crc32(strtolower($email));
        //create user privledges


        $permission = '00000000000v667wt0\nhwba88000000\nm6adbfhra0hs';

        //make sure the current username is not already in use at the forums.  if it is, do not insert the data
        $result3 = $this->CI->db->query("SELECT * FROM phpbb_users WHERE username='$username'");
        $num = $result3->num_rows();
        if ($num != 0) {
            return array(
                'status' => false,
                'msg' => 'Username already taken.'
            );
        } else {
            $_SESSION['forumnametaken'] = 0;
            $this->CI->db->query("INSERT INTO phpbb_users
			(user_type, group_id, user_permissions, user_perm_from, user_ip, user_regdate, username, username_clean, user_password, user_passchg, user_email, user_email_hash, user_lastvisit, user_lastmark, user_lastpost_time, user_last_search, user_warnings, user_last_warning, user_login_attempts, user_inactive_reason, user_inactive_time, user_posts, user_lang, user_timezone, 
			
			
			user_dateformat, user_style, user_rank, user_new_privmsg, user_unread_privmsg, user_last_privmsg, user_message_rules, user_full_folder, user_emailtime, user_topic_show_days, user_topic_sortby_type, user_topic_sortby_dir, user_post_show_days, user_post_sortby_type, user_post_sortby_dir, user_notify, user_notify_pm, user_notify_type, user_allow_pm, user_allow_viewonline, user_allow_viewemail, user_allow_massemail, user_options) VALUES('0', '2', '$permission', '0', '$ip', '$user_regdate', '$username', '$username_clean', '$password', '$user_regdate',  '$email', '$user_email_hash', '0', '$user_regdate', '0', '0', '0', '0', '0', '0', '0', '0', 'en', '-8:00', 'D M d, Y g:i a', '1', '0', '0', '0', '0', '0', '-3', '0', '0', 't', 'd', '0', 't', 'a', '0','1', '0', '1', '1', '1', '1', '895')");
            //or die(mysql_error());
            //10, 19, 29, 36, 43, 49


            $query = $this->CI->db->query("SELECT * FROM phpbb_users WHERE username='$username' AND user_password='$password'");
            $row = $query->row();
            if (isset($row)) {
                $user_id = $row->user_id;
                // User successfully reqistered
            }
            //	$schoolwithstate = $schoolname.', '.$schoolstate;
            //	$this->db->query("INSERT INTO phpbb_profile_fields_data(user_id, pf_school) VALUES('$user_id', '$schoolwithstate')");

            //Now update forum necessary tables like num of users, new user id, new user username
            $result5 = $this->CI->db->query("SELECT * FROM phpbb_config WHERE config_name='num_users'");
            $row5 = $result5->row();
            $num_users = $row5->config_value;
            $num_users++;

            //write all the new info to the database
            $this->CI->db->query("UPDATE phpbb_config SET config_value='$num_users' WHERE config_name='num_users'");

            $this->CI->db->query("UPDATE phpbb_config SET config_value='$user_id' WHERE config_name='newest_user_id'");

            $this->CI->db->query("UPDATE phpbb_config SET config_value='$username' WHERE config_name='newest_username'");
            
            return array(
                'status' => true,
                'uid' => $user_id,
                'msg' => 'User registration successfull'
            );
        }
        //$passwords_manager = $phpbb_container->get('passwords.manager');
    }

    /**
     * Returns information from the user data array.
     *
     * @param string $key Item key.
     *
     * @return string/boolean User information on success, FALSE otherwise.
     */
    public function getUserInfo($key)
    {
        if (array_key_exists($key, $this->_user->data))
        {
            return $this->_user->data[$key];
        }
        else
        {
            return FALSE;
        }
    }

    /**
     * Returns user status.
     *
     * @return boolean TRUE is user is logged in, FALSE otherwise.
     */
    public function isLoggedIn()
    {
        return $this->_user->data['is_registered'];
    }

    /**
     * Checks if the currently logged-in user is an administrator.
     *
     * @return boolean TRUE if the currently logged-in user is an administrator, FALSE otherwise.
     */
    public function isAdministrator()
    {
        return $this->isGroupMember('administrators');
    }

    /**
     * Checks if the currently logged-in user is a moderator.
     *
     * @return boolean TRUE if the currently logged-in user is a moderator, FALSE otherwise.
     */
    public function isModerator()
    {
        return  $this->isGroupMember('moderators');
    }

    /**
     * Checks if a user is a member of the given user group.
     *
     * @param string $group Group name in lowercase.
     *
     * @return boolean TRUE if user is a group member, FALSE otherwise.
     */
    public function isGroupMember($group)
    {
        $groups = array_map(strtolower, $this->getUserGroupMembership());

        if (in_array($group, $groups))
        {
            return TRUE;
        }
        else
        {
            return FALSE;
        }
    }

    /**
     * Returns information for a given user.
     *
     * @param int $userId User ID.
     *
     * @return array/boolean Array with user information on success, FALSE otherwise.
     */
    public function getUserById($userId)
    {
        global $table_prefix;

        $this->CI->db->select('*');
        $this->CI->db->from($table_prefix . 'users');
        $this->CI->db->where('user_id', $userId);
        $this->CI->db->limit(1);

        $query = $this->CI->db->get();

        if ($query->num_rows() == 1)
        {
            return $query->row_array();
        }
        else
        {
            return FALSE;
        }
    }

    /**
     * Returns information for a given user.
     *
     * @param string $username User name.
     *
     * @return array/boolean Array with user information on success, FALSE otherwise.
     */
    public function getUserByName($username)
    {
        global $table_prefix;

        $this->CI->db->select('*');
        $this->CI->db->from($table_prefix . 'users');
        $this->CI->db->where('username', $username);
        $this->CI->db->limit(1);

        $query = $this->CI->db->get();

        if ($query->num_rows() == 1)
        {
            return $query->row_array();
        }
        else
        {
            return FALSE;
        }
    }

    /**
     * Returns all user groups.
     *
     * @return array User groups.
     */
    public function getUserGroupMembership()
    {
        global $table_prefix;

        $userId = $this->_user->data['user_id'];

        $this->CI->db->select('g.group_name');
        $this->CI->db->from($table_prefix . 'groups g');
        $this->CI->db->from($table_prefix . 'user_group u');
        $this->CI->db->where('u.user_id', $userId);
        $this->CI->db->where('u.group_id', 'g.group_id', FALSE);

        $query = $this->CI->db->get();

        foreach ($query->result_array() as $group)
        {
            $groups[] = $group['group_name'];
        }

        return $groups;
    }

     
    /*
     * Below all the function taken from test controller on 19 Nov 2017 by MJV
     */
    //Taken from test controller 
    
    function phpbb_hash($password)
    {
            $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

            $random_state = $this->unique_id();
            $random = '';
            $count = 6;

            if (($fh = @fopen('/dev/urandom', 'rb')))
            {
                    $random = fread($fh, $count);
                    fclose($fh);
            }

            if (strlen($random) < $count)
            {
                    $random = '';

                    for ($i = 0; $i < $count; $i += 16)
                    {
                            $random_state = md5($this->unique_id() . $random_state);
                            $random .= pack('H*', md5($random_state));
                    }
                    $random = substr($random, 0, $count);
            }

            $hash = $this->_hash_crypt_private($password, $this->_hash_gensalt_private($random, $itoa64), $itoa64);

            if (strlen($hash) == 34)
            {
                    return $hash;
            }

            return md5($password);
    }

    /**
    * Check for correct password
    */
    function phpbb_check_hash($password, $hash)
    {
            $itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
            if (strlen($hash) == 34)
            {
                    return ($this->_hash_crypt_private($password, $hash, $itoa64) === $hash) ? true : false;
            }

            return (md5($password) === $hash) ? true : false;
    }

    /**
    * Generate salt for hash generation
    */
    function _hash_gensalt_private($input, &$itoa64, $iteration_count_log2 = 6)
    {
            if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31)
            {
                    $iteration_count_log2 = 8;
            }

            $output = '$H$';
            $output .= $itoa64[min($iteration_count_log2 + ((PHP_VERSION >= 5) ? 5 : 3), 30)];
            $output .= $this->_hash_encode64($input, 6, $itoa64);

            return $output;
    }

    /**
    * Encode hash
    */
    function _hash_encode64($input, $count, &$itoa64)
    {
            $output = '';
            $i = 0;

            do
            {
                    $value = ord($input[$i++]);
                    $output .= $itoa64[$value & 0x3f];

                    if ($i < $count)
                    {
                            $value |= ord($input[$i]) << 8;
                    }

                    $output .= $itoa64[($value >> 6) & 0x3f];

                    if ($i++ >= $count)
                    {
                            break;
                    }

                    if ($i < $count)
                    {
                            $value |= ord($input[$i]) << 16;
                    }

                    $output .= $itoa64[($value >> 12) & 0x3f];

                    if ($i++ >= $count)
                    {
                            break;
                    }

                    $output .= $itoa64[($value >> 18) & 0x3f];
            }
            while ($i < $count);

            return $output;
    }

    /**
    * The crypt function/replacement
    */
    function _hash_crypt_private($password, $setting, &$itoa64)
    {
            $output = '*';

            // Check for correct hash
            if (substr($setting, 0, 3) != '$H$')
            {
                    return $output;
            }

            $count_log2 = strpos($itoa64, $setting[3]);

            if ($count_log2 < 7 || $count_log2 > 30)
            {
                    return $output;
            }

            $count = 1 << $count_log2;
            $salt = substr($setting, 4, 8);

            if (strlen($salt) != 8)
            {
                    return $output;
            }

            /**
            * We're kind of forced to use MD5 here since it's the only
            * cryptographic primitive available in all versions of PHP
            * currently in use.  To implement our own low-level crypto
            * in PHP would result in much worse performance and
            * consequently in lower iteration counts and hashes that are
            * quicker to crack (by non-PHP code).
            */
            if (PHP_VERSION >= 5)
            {
                    $hash = md5($salt . $password, true);
                    do
                    {
                            $hash = md5($hash . $password, true);
                    }
                    while (--$count);
            }
            else
            {
                    $hash = pack('H*', md5($salt . $password));
                    do
                    {
                            $hash = pack('H*', md5($hash . $password));
                    }
                    while (--$count);
            }

            $output = substr($setting, 0, 12);
            $output .= $this->_hash_encode64($hash, 16, $itoa64);

            return $output;
    }

    /**
    * Return unique id
    * @param string $extra additional entropy
    */
    function unique_id($extra = 'c')
    {
            static $dss_seeded = false;
            global $config;

            $val = $config['rand_seed'] . microtime();
            $val = md5($val);
            /*
            $config['rand_seed'] = md5($config['rand_seed'] . $val . $extra);

            if ($dss_seeded !== true && ($config['rand_seed_last_update'] < time() - rand(1,10)))
            {
                    set_config('rand_seed', $config['rand_seed'], true);
                    set_config('rand_seed_last_update', time(), true);
                    $dss_seeded = true;
            }
            */
            return substr($val, 4, 16);
    }
}

/* End of file phpbb_library.php */
/* Location: ./application/libraries/phpbb_library.php */