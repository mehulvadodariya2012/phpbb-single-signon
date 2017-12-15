##  PHPbb Single SignOn Class for PHP Frameworks 

This library is developed to perform single sign on operation from Main website to PHPbb Forum.

### Getting Started

#### Using Codeigniter 
```
$this->load->library('phpbb');
$this->phpbb->registerUser($uEmail,$uPassword,$uEmail,$uIP);
```

#### Other Method
```
require_once 'path_to_file/Phpbb.php';
$obj = new Phpbb();
```


### Create PHPbb session without password. 

This function will return user information with Session id 

```
$obj->loginUserWithoutPassword($phpbbUserId);
```

After successfully getting Session Id you have to pass this on forum URL 

e.g.[http://www.youdomain.domain/index.php?sid=longsessionidhash](#)



### Create PHPbb session using password. 

This function will return user information with Session id 

```
$obj->loginUser($username,$password,$autologin);
```

After successfully getting Session Id you have to pass this on forum URL 


### Destroy PHPbb session id. 

This function will destroy specific session id

```
$obj->logoutUser($sessioID,$userID);
```

### User Registration

 Register user to PHPbb
 * @param String $username User username 
 * @param String $password Users password
 * @param String $email user email address
 * @param IP $ip user current ip address

```
$obj->registerUser($username,$password,$email,$ip);
```

### User Info

Returns information from the user data array.

```
$obj->getUserInfo($key);
```


### Check Login status

Returns user status. return boolean TRUE is user is logged in, FALSE otherwise.

```
$obj->isLoggedIn();
```


### Check admin status

Checks if the currently logged-in user is an administrator. return boolean TRUE if the currently logged-in user is an administrator, FALSE otherwise.

```
$obj->isAdministrator();
```
