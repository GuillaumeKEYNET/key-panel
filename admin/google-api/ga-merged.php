<?php
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * The Google API Client
 * http://code.google.com/p/google-api-php-client/
 */
class Google_Client
{
  const LIBVER = "1.1.3";
  const USER_AGENT_SUFFIX = "google-api-php-client/";
  /**
   * @var Google_Auth_Abstract $auth
   */
  private $auth;

  /**
   * @var Google_IO_Abstract $io
   */
  private $io;

  /**
   * @var Google_Cache_Abstract $cache
   */
  private $cache;

  /**
   * @var Google_Config $config
   */
  private $config;

  /**
   * @var Google_Logger_Abstract $logger
   */
  private $logger;

  /**
   * @var boolean $deferExecution
   */
  private $deferExecution = false;

  /** @var array $scopes */
  // Scopes requested by the client
  protected $requestedScopes = array();

  // definitions of services that are discovered.
  protected $services = array();

  // Used to track authenticated state, can't discover services after doing authenticate()
  private $authenticated = false;

  /**
   * Construct the Google Client.
   *
   * @param $config Google_Config or string for the ini file to load
   */
  public function __construct($config = null)
  {
    if (is_string($config) && strlen($config)) {
      $config = new Google_Config($config);
    } else if ( !($config instanceof Google_Config)) {
      $config = new Google_Config();

      if ($this->isAppEngine()) {
        // Automatically use Memcache if we're in AppEngine.
        $config->setCacheClass('Google_Cache_Memcache');
      }

      if (version_compare(phpversion(), "5.3.4", "<=") || $this->isAppEngine()) {
        // Automatically disable compress.zlib, as currently unsupported.
        $config->setClassConfig('Google_Http_Request', 'disable_gzip', true);
      }
    }

    if ($config->getIoClass() == Google_Config::USE_AUTO_IO_SELECTION) {
      if (function_exists('curl_version') && function_exists('curl_exec')
          && !$this->isAppEngine()) {
        $config->setIoClass("Google_IO_Curl");
      } else {
        $config->setIoClass("Google_IO_Stream");
      }
    }

    $this->config = $config;
  }

  /**
   * Get a string containing the version of the library.
   *
   * @return string
   */
  public function getLibraryVersion()
  {
    return self::LIBVER;
  }

  /**
   * Attempt to exchange a code for an valid authentication token.
   * Helper wrapped around the OAuth 2.0 implementation.
   *
   * @param $code string code from accounts.google.com
   * @return string token
   */
  public function authenticate($code)
  {
    $this->authenticated = true;
    return $this->getAuth()->authenticate($code);
  }
  
  /**
   * Loads a service account key and parameters from a JSON 
   * file from the Google Developer Console. Uses that and the
   * given array of scopes to return an assertion credential for 
   * use with refreshTokenWithAssertionCredential. 
   *
   * @param string $jsonLocation File location of the project-key.json.
   * @param array $scopes The scopes to assert.
   * @return Google_Auth_AssertionCredentials.
   * @
   */
  public function loadServiceAccountJson($jsonLocation, $scopes)
  {
    $data = json_decode(file_get_contents($jsonLocation));
    if (isset($data->type) && $data->type == 'service_account') {
      // Service Account format.
      $cred = new Google_Auth_AssertionCredentials(
          $data->client_email,
          $scopes,
          $data->private_key
      );
      return $cred;
    } else {
      throw new Google_Exception("Invalid service account JSON file.");
    }
  }

  /**
   * Set the auth config from the JSON string provided.
   * This structure should match the file downloaded from
   * the "Download JSON" button on in the Google Developer
   * Console.
   * @param string $json the configuration json
   * @throws Google_Exception
   */
  public function setAuthConfig($json)
  {
    $data = json_decode($json);
    $key = isset($data->installed) ? 'installed' : 'web';
    if (!isset($data->$key)) {
      throw new Google_Exception("Invalid client secret JSON file.");
    }
    $this->setClientId($data->$key->client_id);
    $this->setClientSecret($data->$key->client_secret);
    if (isset($data->$key->redirect_uris)) {
      $this->setRedirectUri($data->$key->redirect_uris[0]);
    }
  }

  /**
   * Set the auth config from the JSON file in the path
   * provided. This should match the file downloaded from
   * the "Download JSON" button on in the Google Developer
   * Console.
   * @param string $file the file location of the client json
   */
  public function setAuthConfigFile($file)
  {
    $this->setAuthConfig(file_get_contents($file));
  }

  /**
   * @throws Google_Auth_Exception
   * @return array
   * @visible For Testing
   */
  public function prepareScopes()
  {
    if (empty($this->requestedScopes)) {
      throw new Google_Auth_Exception("No scopes specified");
    }
    $scopes = implode(' ', $this->requestedScopes);
    return $scopes;
  }

  /**
   * Set the OAuth 2.0 access token using the string that resulted from calling createAuthUrl()
   * or Google_Client#getAccessToken().
   * @param string $accessToken JSON encoded string containing in the following format:
   * {"access_token":"TOKEN", "refresh_token":"TOKEN", "token_type":"Bearer",
   *  "expires_in":3600, "id_token":"TOKEN", "created":1320790426}
   */
  public function setAccessToken($accessToken)
  {
    if ($accessToken == 'null') {
      $accessToken = null;
    }
    $this->getAuth()->setAccessToken($accessToken);
  }



  /**
   * Set the authenticator object
   * @param Google_Auth_Abstract $auth
   */
  public function setAuth(Google_Auth_Abstract $auth)
  {
    $this->config->setAuthClass(get_class($auth));
    $this->auth = $auth;
  }

  /**
   * Set the IO object
   * @param Google_IO_Abstract $io
   */
  public function setIo(Google_IO_Abstract $io)
  {
    $this->config->setIoClass(get_class($io));
    $this->io = $io;
  }

  /**
   * Set the Cache object
   * @param Google_Cache_Abstract $cache
   */
  public function setCache(Google_Cache_Abstract $cache)
  {
    $this->config->setCacheClass(get_class($cache));
    $this->cache = $cache;
  }

  /**
   * Set the Logger object
   * @param Google_Logger_Abstract $logger
   */
  public function setLogger(Google_Logger_Abstract $logger)
  {
    $this->config->setLoggerClass(get_class($logger));
    $this->logger = $logger;
  }

  /**
   * Construct the OAuth 2.0 authorization request URI.
   * @return string
   */
  public function createAuthUrl()
  {
    $scopes = $this->prepareScopes();
    return $this->getAuth()->createAuthUrl($scopes);
  }

  /**
   * Get the OAuth 2.0 access token.
   * @return string $accessToken JSON encoded string in the following format:
   * {"access_token":"TOKEN", "refresh_token":"TOKEN", "token_type":"Bearer",
   *  "expires_in":3600,"id_token":"TOKEN", "created":1320790426}
   */
  public function getAccessToken()
  {
    $token = $this->getAuth()->getAccessToken();
    // The response is json encoded, so could be the string null.
    // It is arguable whether this check should be here or lower
    // in the library.
    return (null == $token || 'null' == $token || '[]' == $token) ? null : $token;
  }

  /**
   * Get the OAuth 2.0 refresh token.
   * @return string $refreshToken refresh token or null if not available
   */
  public function getRefreshToken()
  {
    return $this->getAuth()->getRefreshToken();
  }

  /**
   * Returns if the access_token is expired.
   * @return bool Returns True if the access_token is expired.
   */
  public function isAccessTokenExpired()
  {
    return $this->getAuth()->isAccessTokenExpired();
  }

  /**
   * Set OAuth 2.0 "state" parameter to achieve per-request customization.
   * @see http://tools.ietf.org/html/draft-ietf-oauth-v2-22#section-3.1.2.2
   * @param string $state
   */
  public function setState($state)
  {
    $this->getAuth()->setState($state);
  }

  /**
   * @param string $accessType Possible values for access_type include:
   *  {@code "offline"} to request offline access from the user.
   *  {@code "online"} to request online access from the user.
   */
  public function setAccessType($accessType)
  {
    $this->config->setAccessType($accessType);
  }

  /**
   * @param string $approvalPrompt Possible values for approval_prompt include:
   *  {@code "force"} to force the approval UI to appear. (This is the default value)
   *  {@code "auto"} to request auto-approval when possible.
   */
  public function setApprovalPrompt($approvalPrompt)
  {
    $this->config->setApprovalPrompt($approvalPrompt);
  }

  /**
   * Set the login hint, email address or sub id.
   * @param string $loginHint
   */
  public function setLoginHint($loginHint)
  {
      $this->config->setLoginHint($loginHint);
  }

  /**
   * Set the application name, this is included in the User-Agent HTTP header.
   * @param string $applicationName
   */
  public function setApplicationName($applicationName)
  {
    $this->config->setApplicationName($applicationName);
  }

  /**
   * Set the OAuth 2.0 Client ID.
   * @param string $clientId
   */
  public function setClientId($clientId)
  {
    $this->config->setClientId($clientId);
  }

  /**
   * Set the OAuth 2.0 Client Secret.
   * @param string $clientSecret
   */
  public function setClientSecret($clientSecret)
  {
    $this->config->setClientSecret($clientSecret);
  }

  /**
   * Set the OAuth 2.0 Redirect URI.
   * @param string $redirectUri
   */
  public function setRedirectUri($redirectUri)
  {
    $this->config->setRedirectUri($redirectUri);
  }

  /**
   * If 'plus.login' is included in the list of requested scopes, you can use
   * this method to define types of app activities that your app will write.
   * You can find a list of available types here:
   * @link https://developers.google.com/+/api/moment-types
   *
   * @param array $requestVisibleActions Array of app activity types
   */
  public function setRequestVisibleActions($requestVisibleActions)
  {
    if (is_array($requestVisibleActions)) {
      $requestVisibleActions = join(" ", $requestVisibleActions);
    }
    $this->config->setRequestVisibleActions($requestVisibleActions);
  }

  /**
   * Set the developer key to use, these are obtained through the API Console.
   * @see http://code.google.com/apis/console-help/#generatingdevkeys
   * @param string $developerKey
   */
  public function setDeveloperKey($developerKey)
  {
    $this->config->setDeveloperKey($developerKey);
  }

  /**
   * Set the hd (hosted domain) parameter streamlines the login process for
   * Google Apps hosted accounts. By including the domain of the user, you
   * restrict sign-in to accounts at that domain.
   * @param $hd string - the domain to use.
   */
  public function setHostedDomain($hd)
  {
    $this->config->setHostedDomain($hd);
  }

  /**
   * Set the prompt hint. Valid values are none, consent and select_account.
   * If no value is specified and the user has not previously authorized
   * access, then the user is shown a consent screen.
   * @param $prompt string
   */
  public function setPrompt($prompt)
  {
    $this->config->setPrompt($prompt);
  }

  /**
   * openid.realm is a parameter from the OpenID 2.0 protocol, not from OAuth
   * 2.0. It is used in OpenID 2.0 requests to signify the URL-space for which
   * an authentication request is valid.
   * @param $realm string - the URL-space to use.
   */
  public function setOpenidRealm($realm)
  {
    $this->config->setOpenidRealm($realm);
  }

  /**
   * If this is provided with the value true, and the authorization request is
   * granted, the authorization will include any previous authorizations
   * granted to this user/application combination for other scopes.
   * @param $include boolean - the URL-space to use.
   */
  public function setIncludeGrantedScopes($include)
  {
    $this->config->setIncludeGrantedScopes($include);
  }

  /**
   * Fetches a fresh OAuth 2.0 access token with the given refresh token.
   * @param string $refreshToken
   */
  public function refreshToken($refreshToken)
  {
    $this->getAuth()->refreshToken($refreshToken);
  }

  /**
   * Revoke an OAuth2 access token or refresh token. This method will revoke the current access
   * token, if a token isn't provided.
   * @throws Google_Auth_Exception
   * @param string|null $token The token (access token or a refresh token) that should be revoked.
   * @return boolean Returns True if the revocation was successful, otherwise False.
   */
  public function revokeToken($token = null)
  {
    return $this->getAuth()->revokeToken($token);
  }

  /**
   * Verify an id_token. This method will verify the current id_token, if one
   * isn't provided.
   * @throws Google_Auth_Exception
   * @param string|null $token The token (id_token) that should be verified.
   * @return Google_Auth_LoginTicket Returns an apiLoginTicket if the verification was
   * successful.
   */
  public function verifyIdToken($token = null)
  {
    return $this->getAuth()->verifyIdToken($token);
  }

  /**
   * Verify a JWT that was signed with your own certificates.
   *
   * @param $id_token string The JWT token
   * @param $cert_location array of certificates
   * @param $audience string the expected consumer of the token
   * @param $issuer string the expected issuer, defaults to Google
   * @param [$max_expiry] the max lifetime of a token, defaults to MAX_TOKEN_LIFETIME_SECS
   * @return mixed token information if valid, false if not
   */
  public function verifySignedJwt($id_token, $cert_location, $audience, $issuer, $max_expiry = null)
  {
    $auth = new Google_Auth_OAuth2($this);
    $certs = $auth->retrieveCertsFromLocation($cert_location);
    return $auth->verifySignedJwtWithCerts($id_token, $certs, $audience, $issuer, $max_expiry);
  }

  /**
   * @param $creds Google_Auth_AssertionCredentials
   */
  public function setAssertionCredentials(Google_Auth_AssertionCredentials $creds)
  {
    $this->getAuth()->setAssertionCredentials($creds);
  }

  /**
   * Set the scopes to be requested. Must be called before createAuthUrl().
   * Will remove any previously configured scopes.
   * @param array $scopes, ie: array('https://www.googleapis.com/auth/plus.login',
   * 'https://www.googleapis.com/auth/moderator')
   */
  public function setScopes($scopes)
  {
    $this->requestedScopes = array();
    $this->addScope($scopes);
  }

  /**
   * This functions adds a scope to be requested as part of the OAuth2.0 flow.
   * Will append any scopes not previously requested to the scope parameter.
   * A single string will be treated as a scope to request. An array of strings
   * will each be appended.
   * @param $scope_or_scopes string|array e.g. "profile"
   */
  public function addScope($scope_or_scopes)
  {
    if (is_string($scope_or_scopes) && !in_array($scope_or_scopes, $this->requestedScopes)) {
      $this->requestedScopes[] = $scope_or_scopes;
    } else if (is_array($scope_or_scopes)) {
      foreach ($scope_or_scopes as $scope) {
        $this->addScope($scope);
      }
    }
  }

  /**
   * Returns the list of scopes requested by the client
   * @return array the list of scopes
   *
   */
  public function getScopes()
  {
     return $this->requestedScopes;
  }

  /**
   * Declare whether batch calls should be used. This may increase throughput
   * by making multiple requests in one connection.
   *
   * @param boolean $useBatch True if the batch support should
   * be enabled. Defaults to False.
   */
  public function setUseBatch($useBatch)
  {
    // This is actually an alias for setDefer.
    $this->setDefer($useBatch);
  }

  /**
   * Declare whether making API calls should make the call immediately, or
   * return a request which can be called with ->execute();
   *
   * @param boolean $defer True if calls should not be executed right away.
   */
  public function setDefer($defer)
  {
    $this->deferExecution = $defer;
  }

  /**
   * Helper method to execute deferred HTTP requests.
   *
   * @param $request Google_Http_Request|Google_Http_Batch
   * @throws Google_Exception
   * @return object of the type of the expected class or array.
   */
  public function execute($request)
  {
    if ($request instanceof Google_Http_Request) {
      $request->setUserAgent(
          $this->getApplicationName()
          . " " . self::USER_AGENT_SUFFIX
          . $this->getLibraryVersion()
      );
      if (!$this->getClassConfig("Google_Http_Request", "disable_gzip")) {
        $request->enableGzip();
      }
      $request->maybeMoveParametersToBody();
      return Google_Http_REST::execute($this, $request);
    } else if ($request instanceof Google_Http_Batch) {
      return $request->execute();
    } else {
      throw new Google_Exception("Do not know how to execute this type of object.");
    }
  }

  /**
   * Whether or not to return raw requests
   * @return boolean
   */
  public function shouldDefer()
  {
    return $this->deferExecution;
  }

  /**
   * @return Google_Auth_Abstract Authentication implementation
   */
  public function getAuth()
  {
    if (!isset($this->auth)) {
      $class = $this->config->getAuthClass();
      $this->auth = new $class($this);
    }
    return $this->auth;
  }

  /**
   * @return Google_IO_Abstract IO implementation
   */
  public function getIo()
  {
    if (!isset($this->io)) {
      $class = $this->config->getIoClass();
      $this->io = new $class($this);
    }
    return $this->io;
  }

  /**
   * @return Google_Cache_Abstract Cache implementation
   */
  public function getCache()
  {
    if (!isset($this->cache)) {
      $class = $this->config->getCacheClass();
      $this->cache = new $class($this);
    }
    return $this->cache;
  }

  /**
   * @return Google_Logger_Abstract Logger implementation
   */
  public function getLogger()
  {
    if (!isset($this->logger)) {
      $class = $this->config->getLoggerClass();
      $this->logger = new $class($this);
    }
    return $this->logger;
  }

  /**
   * Retrieve custom configuration for a specific class.
   * @param $class string|object - class or instance of class to retrieve
   * @param $key string optional - key to retrieve
   * @return array
   */
  public function getClassConfig($class, $key = null)
  {
    if (!is_string($class)) {
      $class = get_class($class);
    }
    return $this->config->getClassConfig($class, $key);
  }

  /**
   * Set configuration specific to a given class.
   * $config->setClassConfig('Google_Cache_File',
   *   array('directory' => '/tmp/cache'));
   * @param $class string|object - The class name for the configuration
   * @param $config string key or an array of configuration values
   * @param $value string optional - if $config is a key, the value
   *
   */
  public function setClassConfig($class, $config, $value = null)
  {
    if (!is_string($class)) {
      $class = get_class($class);
    }
    $this->config->setClassConfig($class, $config, $value);

  }

  /**
   * @return string the base URL to use for calls to the APIs
   */
  public function getBasePath()
  {
    return $this->config->getBasePath();
  }

  /**
   * @return string the name of the application
   */
  public function getApplicationName()
  {
    return $this->config->getApplicationName();
  }

  /**
   * Are we running in Google AppEngine?
   * return bool
   */
  public function isAppEngine()
  {
    return (isset($_SERVER['SERVER_SOFTWARE']) &&
        strpos($_SERVER['SERVER_SOFTWARE'], 'Google App Engine') !== false);
  }
}
 

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}


/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * A class to contain the library configuration for the Google API client.
 */
class Google_Config
{
  const GZIP_DISABLED = true;
  const GZIP_ENABLED = false;
  const GZIP_UPLOADS_ENABLED = true;
  const GZIP_UPLOADS_DISABLED = false;
  const USE_AUTO_IO_SELECTION = "auto";
  const TASK_RETRY_NEVER = 0;
  const TASK_RETRY_ONCE = 1;
  const TASK_RETRY_ALWAYS = -1;
  protected $configuration;

  /**
   * Create a new Google_Config. Can accept an ini file location with the
   * local configuration. For example:
   *     application_name="My App"
   *
   * @param [$ini_file_location] - optional - The location of the ini file to load
   */
  public function __construct($ini_file_location = null)
  {
    $this->configuration = array(
      // The application_name is included in the User-Agent HTTP header.
      'application_name' => '',

      // Which Authentication, Storage and HTTP IO classes to use.
      'auth_class'    => 'Google_Auth_OAuth2',
      'io_class'      => self::USE_AUTO_IO_SELECTION,
      'cache_class'   => 'Google_Cache_File',
      'logger_class'  => 'Google_Logger_Null',

      // Don't change these unless you're working against a special development
      // or testing environment.
      'base_path' => 'https://www.googleapis.com',

      // Definition of class specific values, like file paths and so on.
      'classes' => array(
        'Google_IO_Abstract' => array(
          'request_timeout_seconds' => 100,
        ),
        'Google_Logger_Abstract' => array(
          'level' => 'debug',
          'log_format' => "[%datetime%] %level%: %message% %context%\n",
          'date_format' => 'd/M/Y:H:i:s O',
          'allow_newlines' => true
        ),
        'Google_Logger_File' => array(
          'file' => 'php://stdout',
          'mode' => 0640,
          'lock' => false,
        ),
        'Google_Http_Request' => array(
          // Disable the use of gzip on calls if set to true. Defaults to false.
          'disable_gzip' => self::GZIP_ENABLED,

          // We default gzip to disabled on uploads even if gzip is otherwise
          // enabled, due to some issues seen with small packet sizes for uploads.
          // Please test with this option before enabling gzip for uploads in
          // a production environment.
          'enable_gzip_for_uploads' => self::GZIP_UPLOADS_DISABLED,
        ),
        // If you want to pass in OAuth 2.0 settings, they will need to be
        // structured like this.
        'Google_Auth_OAuth2' => array(
          // Keys for OAuth 2.0 access, see the API console at
          // https://developers.google.com/console
          'client_id' => '',
          'client_secret' => '',
          'redirect_uri' => '',

          // Simple API access key, also from the API console. Ensure you get
          // a Server key, and not a Browser key.
          'developer_key' => '',

          // Other parameters.
          'hd' => '',
          'prompt' => '',
          'openid.realm' => '',
          'include_granted_scopes' => '',
          'login_hint' => '',
          'request_visible_actions' => '',
          'access_type' => 'online',
          'approval_prompt' => 'auto',
          'federated_signon_certs_url' =>
              'https://www.googleapis.com/oauth2/v1/certs',
        ),
        'Google_Task_Runner' => array(
          // Delays are specified in seconds
          'initial_delay' => 1,
          'max_delay' => 60,
          // Base number for exponential backoff
          'factor' => 2,
          // A random number between -jitter and jitter will be added to the
          // factor on each iteration to allow for better distribution of
          // retries.
          'jitter' => .5,
          // Maximum number of retries allowed
          'retries' => 0
        ),
        'Google_Service_Exception' => array(
          'retry_map' => array(
            '500' => self::TASK_RETRY_ALWAYS,
            '503' => self::TASK_RETRY_ALWAYS,
            'rateLimitExceeded' => self::TASK_RETRY_ALWAYS,
            'userRateLimitExceeded' => self::TASK_RETRY_ALWAYS
          )
        ),
        'Google_IO_Exception' => array(
          'retry_map' => !extension_loaded('curl') ? array() : array(
            CURLE_COULDNT_RESOLVE_HOST => self::TASK_RETRY_ALWAYS,
            CURLE_COULDNT_CONNECT => self::TASK_RETRY_ALWAYS,
            CURLE_OPERATION_TIMEOUTED => self::TASK_RETRY_ALWAYS,
            CURLE_SSL_CONNECT_ERROR => self::TASK_RETRY_ALWAYS,
            CURLE_GOT_NOTHING => self::TASK_RETRY_ALWAYS
          )
        ),
        // Set a default directory for the file cache.
        'Google_Cache_File' => array(
          'directory' => sys_get_temp_dir() . '/Google_Client'
        )
      ),
    );
    if ($ini_file_location) {
      $ini = parse_ini_file($ini_file_location, true);
      if (is_array($ini) && count($ini)) {
        $merged_configuration = $ini + $this->configuration;
        if (isset($ini['classes']) && isset($this->configuration['classes'])) {
          $merged_configuration['classes'] = $ini['classes'] + $this->configuration['classes'];
        }
        $this->configuration = $merged_configuration;
      }
    }
  }

  /**
   * Set configuration specific to a given class.
   * $config->setClassConfig('Google_Cache_File',
   *   array('directory' => '/tmp/cache'));
   * @param $class string The class name for the configuration
   * @param $config string key or an array of configuration values
   * @param $value string optional - if $config is a key, the value
   */
  public function setClassConfig($class, $config, $value = null)
  {
    if (!is_array($config)) {
      if (!isset($this->configuration['classes'][$class])) {
        $this->configuration['classes'][$class] = array();
      }
      $this->configuration['classes'][$class][$config] = $value;
    } else {
      $this->configuration['classes'][$class] = $config;
    }
  }

  public function getClassConfig($class, $key = null)
  {
    if (!isset($this->configuration['classes'][$class])) {
      return null;
    }
    if ($key === null) {
      return $this->configuration['classes'][$class];
    } else {
      return $this->configuration['classes'][$class][$key];
    }
  }

  /**
   * Return the configured cache class.
   * @return string
   */
  public function getCacheClass()
  {
    return $this->configuration['cache_class'];
  }

  /**
   * Return the configured logger class.
   * @return string
   */
  public function getLoggerClass()
  {
    return $this->configuration['logger_class'];
  }

  /**
   * Return the configured Auth class.
   * @return string
   */
  public function getAuthClass()
  {
    return $this->configuration['auth_class'];
  }

  /**
   * Set the auth class.
   *
   * @param $class string the class name to set
   */
  public function setAuthClass($class)
  {
    $prev = $this->configuration['auth_class'];
    if (!isset($this->configuration['classes'][$class]) &&
        isset($this->configuration['classes'][$prev])) {
      $this->configuration['classes'][$class] =
          $this->configuration['classes'][$prev];
    }
    $this->configuration['auth_class'] = $class;
  }

  /**
   * Set the IO class.
   *
   * @param $class string the class name to set
   */
  public function setIoClass($class)
  {
    $prev = $this->configuration['io_class'];
    if (!isset($this->configuration['classes'][$class]) &&
        isset($this->configuration['classes'][$prev])) {
      $this->configuration['classes'][$class] =
          $this->configuration['classes'][$prev];
    }
    $this->configuration['io_class'] = $class;
  }

  /**
   * Set the cache class.
   *
   * @param $class string the class name to set
   */
  public function setCacheClass($class)
  {
    $prev = $this->configuration['cache_class'];
    if (!isset($this->configuration['classes'][$class]) &&
        isset($this->configuration['classes'][$prev])) {
      $this->configuration['classes'][$class] =
          $this->configuration['classes'][$prev];
    }
    $this->configuration['cache_class'] = $class;
  }

  /**
   * Set the logger class.
   *
   * @param $class string the class name to set
   */
  public function setLoggerClass($class)
  {
    $prev = $this->configuration['logger_class'];
    if (!isset($this->configuration['classes'][$class]) &&
        isset($this->configuration['classes'][$prev])) {
      $this->configuration['classes'][$class] =
          $this->configuration['classes'][$prev];
    }
    $this->configuration['logger_class'] = $class;
  }

  /**
   * Return the configured IO class.
   *
   * @return string
   */
  public function getIoClass()
  {
    return $this->configuration['io_class'];
  }

  /**
   * Set the application name, this is included in the User-Agent HTTP header.
   * @param string $name
   */
  public function setApplicationName($name)
  {
    $this->configuration['application_name'] = $name;
  }

  /**
   * @return string the name of the application
   */
  public function getApplicationName()
  {
    return $this->configuration['application_name'];
  }

  /**
   * Set the client ID for the auth class.
   * @param $clientId string - the API console client ID
   */
  public function setClientId($clientId)
  {
    $this->setAuthConfig('client_id', $clientId);
  }

  /**
   * Set the client secret for the auth class.
   * @param $secret string - the API console client secret
   */
  public function setClientSecret($secret)
  {
    $this->setAuthConfig('client_secret', $secret);
  }

  /**
   * Set the redirect uri for the auth class. Note that if using the
   * Javascript based sign in flow, this should be the string 'postmessage'.
   *
   * @param $uri string - the URI that users should be redirected to
   */
  public function setRedirectUri($uri)
  {
    $this->setAuthConfig('redirect_uri', $uri);
  }

  /**
   * Set the app activities for the auth class.
   * @param $rva string a space separated list of app activity types
   */
  public function setRequestVisibleActions($rva)
  {
    $this->setAuthConfig('request_visible_actions', $rva);
  }

  /**
   * Set the the access type requested (offline or online.)
   * @param $access string - the access type
   */
  public function setAccessType($access)
  {
    $this->setAuthConfig('access_type', $access);
  }

  /**
   * Set when to show the approval prompt (auto or force)
   * @param $approval string - the approval request
   */
  public function setApprovalPrompt($approval)
  {
    $this->setAuthConfig('approval_prompt', $approval);
  }

  /**
   * Set the login hint (email address or sub identifier)
   * @param $hint string
   */
  public function setLoginHint($hint)
  {
    $this->setAuthConfig('login_hint', $hint);
  }

  /**
   * Set the developer key for the auth class. Note that this is separate value
   * from the client ID - if it looks like a URL, its a client ID!
   * @param $key string - the API console developer key
   */
  public function setDeveloperKey($key)
  {
    $this->setAuthConfig('developer_key', $key);
  }

  /**
   * Set the hd (hosted domain) parameter streamlines the login process for
   * Google Apps hosted accounts. By including the domain of the user, you
   * restrict sign-in to accounts at that domain. 
   * 
   * This should not be used to ensure security on your application - check
   * the hd values within an id token (@see Google_Auth_LoginTicket) after sign
   * in to ensure that the user is from the domain you were expecting.
   *
   * @param $hd string - the domain to use.
   */
  public function setHostedDomain($hd)
  {
    $this->setAuthConfig('hd', $hd);
  }

  /**
   * Set the prompt hint. Valid values are none, consent and select_account.
   * If no value is specified and the user has not previously authorized
   * access, then the user is shown a consent screen.
   * @param $prompt string
   */
  public function setPrompt($prompt)
  {
    $this->setAuthConfig('prompt', $prompt);
  }

  /**
   * openid.realm is a parameter from the OpenID 2.0 protocol, not from OAuth
   * 2.0. It is used in OpenID 2.0 requests to signify the URL-space for which
   * an authentication request is valid.
   * @param $realm string - the URL-space to use.
   */
  public function setOpenidRealm($realm)
  {
    $this->setAuthConfig('openid.realm', $realm);
  }

  /**
   * If this is provided with the value true, and the authorization request is
   * granted, the authorization will include any previous authorizations
   * granted to this user/application combination for other scopes.
   * @param $include boolean - the URL-space to use.
   */
  public function setIncludeGrantedScopes($include)
  {
    $this->setAuthConfig(
        'include_granted_scopes',
        $include ? "true" : "false"
    );
  }

  /**
   * @return string the base URL to use for API calls
   */
  public function getBasePath()
  {
    return $this->configuration['base_path'];
  }

  /**
   * Set the auth configuration for the current auth class.
   * @param $key - the key to set
   * @param $value - the parameter value
   */
  private function setAuthConfig($key, $value)
  {
    if (!isset($this->configuration['classes'][$this->getAuthClass()])) {
      $this->configuration['classes'][$this->getAuthClass()] = array();
    }
    $this->configuration['classes'][$this->getAuthClass()][$key] = $value;
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class Google_Exception extends Exception
{
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * This class defines attributes, valid values, and usage which is generated
 * from a given json schema.
 * http://tools.ietf.org/html/draft-zyp-json-schema-03#section-5
 *
 */
class Google_Model implements ArrayAccess
{
  /**
   * If you need to specify a NULL JSON value, use Google_Model::NULL_VALUE
   * instead - it will be replaced when converting to JSON with a real null. 
   */
  const NULL_VALUE = "{}gapi-php-null";
  protected $internal_gapi_mappings = array();
  protected $modelData = array();
  protected $processed = array();

  /**
   * Polymorphic - accepts a variable number of arguments dependent
   * on the type of the model subclass.
   */
  final public function __construct()
  {
    if (func_num_args() == 1 && is_array(func_get_arg(0))) {
      // Initialize the model with the array's contents.
      $array = func_get_arg(0);
      $this->mapTypes($array);
    }
    $this->gapiInit();
  }

  /**
   * Getter that handles passthrough access to the data array, and lazy object creation.
   * @param string $key Property name.
   * @return mixed The value if any, or null.
   */
  public function __get($key)
  {
    $keyTypeName = $this->keyType($key);
    $keyDataType = $this->dataType($key);
    if (isset($this->$keyTypeName) && !isset($this->processed[$key])) {
      if (isset($this->modelData[$key])) {
        $val = $this->modelData[$key];
      } else if (isset($this->$keyDataType) &&
          ($this->$keyDataType == 'array' || $this->$keyDataType == 'map')) {
        $val = array();
      } else {
        $val = null;
      }

      if ($this->isAssociativeArray($val)) {
        if (isset($this->$keyDataType) && 'map' == $this->$keyDataType) {
          foreach ($val as $arrayKey => $arrayItem) {
              $this->modelData[$key][$arrayKey] =
                $this->createObjectFromName($keyTypeName, $arrayItem);
          }
        } else {
          $this->modelData[$key] = $this->createObjectFromName($keyTypeName, $val);
        }
      } else if (is_array($val)) {
        $arrayObject = array();
        foreach ($val as $arrayIndex => $arrayItem) {
          $arrayObject[$arrayIndex] =
            $this->createObjectFromName($keyTypeName, $arrayItem);
        }
        $this->modelData[$key] = $arrayObject;
      }
      $this->processed[$key] = true;
    }

    return isset($this->modelData[$key]) ? $this->modelData[$key] : null;
  }

  /**
   * Initialize this object's properties from an array.
   *
   * @param array $array Used to seed this object's properties.
   * @return void
   */
  protected function mapTypes($array)
  {
    // Hard initialise simple types, lazy load more complex ones.
    foreach ($array as $key => $val) {
      if ( !property_exists($this, $this->keyType($key)) &&
        property_exists($this, $key)) {
          $this->$key = $val;
          unset($array[$key]);
      } elseif (property_exists($this, $camelKey = Google_Utils::camelCase($key))) {
          // This checks if property exists as camelCase, leaving it in array as snake_case
          // in case of backwards compatibility issues.
          $this->$camelKey = $val;
      }
    }
    $this->modelData = $array;
  }

  /**
   * Blank initialiser to be used in subclasses to do  post-construction initialisation - this
   * avoids the need for subclasses to have to implement the variadics handling in their
   * constructors.
   */
  protected function gapiInit()
  {
    return;
  }

  /**
   * Create a simplified object suitable for straightforward
   * conversion to JSON. This is relatively expensive
   * due to the usage of reflection, but shouldn't be called
   * a whole lot, and is the most straightforward way to filter.
   */
  public function toSimpleObject()
  {
    $object = new stdClass();

    // Process all other data.
    foreach ($this->modelData as $key => $val) {
      $result = $this->getSimpleValue($val);
      if ($result !== null) {
        $object->$key = $this->nullPlaceholderCheck($result);
      }
    }

    // Process all public properties.
    $reflect = new ReflectionObject($this);
    $props = $reflect->getProperties(ReflectionProperty::IS_PUBLIC);
    foreach ($props as $member) {
      $name = $member->getName();
      $result = $this->getSimpleValue($this->$name);
      if ($result !== null) {
        $name = $this->getMappedName($name);
        $object->$name = $this->nullPlaceholderCheck($result);
      }
    }

    return $object;
  }

  /**
   * Handle different types of values, primarily
   * other objects and map and array data types.
   */
  private function getSimpleValue($value)
  {
    if ($value instanceof Google_Model) {
      return $value->toSimpleObject();
    } else if (is_array($value)) {
      $return = array();
      foreach ($value as $key => $a_value) {
        $a_value = $this->getSimpleValue($a_value);
        if ($a_value !== null) {
          $key = $this->getMappedName($key);
          $return[$key] = $this->nullPlaceholderCheck($a_value);
        }
      }
      return $return;
    }
    return $value;
  }
  
  /**
   * Check whether the value is the null placeholder and return true null.
   */
  private function nullPlaceholderCheck($value)
  {
    if ($value === self::NULL_VALUE) {
      return null;
    }
    return $value;
  }

  /**
   * If there is an internal name mapping, use that.
   */
  private function getMappedName($key)
  {
    if (isset($this->internal_gapi_mappings) &&
        isset($this->internal_gapi_mappings[$key])) {
      $key = $this->internal_gapi_mappings[$key];
    }
    return $key;
  }

  /**
   * Returns true only if the array is associative.
   * @param array $array
   * @return bool True if the array is associative.
   */
  protected function isAssociativeArray($array)
  {
    if (!is_array($array)) {
      return false;
    }
    $keys = array_keys($array);
    foreach ($keys as $key) {
      if (is_string($key)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Given a variable name, discover its type.
   *
   * @param $name
   * @param $item
   * @return object The object from the item.
   */
  private function createObjectFromName($name, $item)
  {
    $type = $this->$name;
    return new $type($item);
  }

  /**
   * Verify if $obj is an array.
   * @throws Google_Exception Thrown if $obj isn't an array.
   * @param array $obj Items that should be validated.
   * @param string $method Method expecting an array as an argument.
   */
  public function assertIsArray($obj, $method)
  {
    if ($obj && !is_array($obj)) {
      throw new Google_Exception(
          "Incorrect parameter type passed to $method(). Expected an array."
      );
    }
  }

  public function offsetExists($offset)
  {
    return isset($this->$offset) || isset($this->modelData[$offset]);
  }

  public function offsetGet($offset)
  {
    return isset($this->$offset) ?
        $this->$offset :
        $this->__get($offset);
  }

  public function offsetSet($offset, $value)
  {
    if (property_exists($this, $offset)) {
      $this->$offset = $value;
    } else {
      $this->modelData[$offset] = $value;
      $this->processed[$offset] = true;
    }
  }

  public function offsetUnset($offset)
  {
    unset($this->modelData[$offset]);
  }

  protected function keyType($key)
  {
    return $key . "Type";
  }

  protected function dataType($key)
  {
    return $key . "DataType";
  }

  public function __isset($key)
  {
    return isset($this->modelData[$key]);
  }

  public function __unset($key)
  {
    unset($this->modelData[$key]);
  }
}

/**
 * Extension to the regular Google_Model that automatically
 * exposes the items array for iteration, so you can just
 * iterate over the object rather than a reference inside.
 */
class Google_Collection extends Google_Model implements Iterator, Countable
{
  protected $collection_key = 'items';

  public function rewind()
  {
    if (isset($this->modelData[$this->collection_key])
        && is_array($this->modelData[$this->collection_key])) {
      reset($this->modelData[$this->collection_key]);
    }
  }

  public function current()
  {
    $this->coerceType($this->key());
    if (is_array($this->modelData[$this->collection_key])) {
      return current($this->modelData[$this->collection_key]);
    }
  }

  public function key()
  {
    if (isset($this->modelData[$this->collection_key])
        && is_array($this->modelData[$this->collection_key])) {
      return key($this->modelData[$this->collection_key]);
    }
  }

  public function next()
  {
    return next($this->modelData[$this->collection_key]);
  }

  public function valid()
  {
    $key = $this->key();
    return $key !== null && $key !== false;
  }

  public function count()
  {
    if (!isset($this->modelData[$this->collection_key])) {
      return 0;
    }
    return count($this->modelData[$this->collection_key]);
  }

  public function offsetExists ($offset)
  {
    if (!is_numeric($offset)) {
      return parent::offsetExists($offset);
    }
    return isset($this->modelData[$this->collection_key][$offset]);
  }

  public function offsetGet($offset)
  {
    if (!is_numeric($offset)) {
      return parent::offsetGet($offset);
    }
    $this->coerceType($offset);
    return $this->modelData[$this->collection_key][$offset];
  }

  public function offsetSet($offset, $value)
  {
    if (!is_numeric($offset)) {
      return parent::offsetSet($offset, $value);
    }
    $this->modelData[$this->collection_key][$offset] = $value;
  }

  public function offsetUnset($offset)
  {
    if (!is_numeric($offset)) {
      return parent::offsetUnset($offset);
    }
    unset($this->modelData[$this->collection_key][$offset]);
  }

  private function coerceType($offset)
  {
    $typeKey = $this->keyType($this->collection_key);
    if (isset($this->$typeKey) && !is_object($this->modelData[$this->collection_key][$offset])) {
      $type = $this->$typeKey;
      $this->modelData[$this->collection_key][$offset] =
          new $type($this->modelData[$this->collection_key][$offset]);
    }
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

class Google_Service
{
  public $version;
  public $servicePath;
  public $availableScopes;
  public $resource;
  private $client;

  public function __construct(Google_Client $client)
  {
    $this->client = $client;
  }

  /**
   * Return the associated Google_Client class.
   * @return Google_Client
   */
  public function getClient()
  {
    return $this->client;
  }
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Collection of static utility methods used for convenience across
 * the client library.
 */
class Google_Utils
{
  public static function urlSafeB64Encode($data)
  {
    $b64 = base64_encode($data);
    $b64 = str_replace(
        array('+', '/', '\r', '\n', '='),
        array('-', '_'),
        $b64
    );
    return $b64;
  }

  public static function urlSafeB64Decode($b64)
  {
    $b64 = str_replace(
        array('-', '_'),
        array('+', '/'),
        $b64
    );
    return base64_decode($b64);
  }

  /**
   * Misc function used to count the number of bytes in a post body, in the
   * world of multi-byte chars and the unpredictability of
   * strlen/mb_strlen/sizeof, this is the only way to do that in a sane
   * manner at the moment.
   *
   * This algorithm was originally developed for the
   * Solar Framework by Paul M. Jones
   *
   * @link   http://solarphp.com/
   * @link   http://svn.solarphp.com/core/trunk/Solar/Json.php
   * @link   http://framework.zend.com/svn/framework/standard/trunk/library/Zend/Json/Decoder.php
   * @param  string $str
   * @return int The number of bytes in a string.
   */
  public static function getStrLen($str)
  {
    $strlenVar = strlen($str);
    $d = $ret = 0;
    for ($count = 0; $count < $strlenVar; ++ $count) {
      $ordinalValue = ord($str{$ret});
      switch (true) {
        case (($ordinalValue >= 0x20) && ($ordinalValue <= 0x7F)):
          // characters U-00000000 - U-0000007F (same as ASCII)
          $ret ++;
          break;
        case (($ordinalValue & 0xE0) == 0xC0):
          // characters U-00000080 - U-000007FF, mask 110XXXXX
          // see http://www.cl.cam.ac.uk/~mgk25/unicode.html#utf-8
          $ret += 2;
          break;
        case (($ordinalValue & 0xF0) == 0xE0):
          // characters U-00000800 - U-0000FFFF, mask 1110XXXX
          // see http://www.cl.cam.ac.uk/~mgk25/unicode.html#utf-8
          $ret += 3;
          break;
        case (($ordinalValue & 0xF8) == 0xF0):
          // characters U-00010000 - U-001FFFFF, mask 11110XXX
          // see http://www.cl.cam.ac.uk/~mgk25/unicode.html#utf-8
          $ret += 4;
          break;
        case (($ordinalValue & 0xFC) == 0xF8):
          // characters U-00200000 - U-03FFFFFF, mask 111110XX
          // see http://www.cl.cam.ac.uk/~mgk25/unicode.html#utf-8
          $ret += 5;
          break;
        case (($ordinalValue & 0xFE) == 0xFC):
          // characters U-04000000 - U-7FFFFFFF, mask 1111110X
          // see http://www.cl.cam.ac.uk/~mgk25/unicode.html#utf-8
          $ret += 6;
          break;
        default:
          $ret ++;
      }
    }
    return $ret;
  }

  /**
   * Normalize all keys in an array to lower-case.
   * @param array $arr
   * @return array Normalized array.
   */
  public static function normalize($arr)
  {
    if (!is_array($arr)) {
      return array();
    }

    $normalized = array();
    foreach ($arr as $key => $val) {
      $normalized[strtolower($key)] = $val;
    }
    return $normalized;
  }

  /**
   * Convert a string to camelCase
   * @param  string $value
   * @return string
   */
  public static function camelCase($value)
  {
    $value = ucwords(str_replace(array('-', '_'), ' ', $value));
    $value = str_replace(' ', '', $value);
    $value[0] = strtolower($value[0]);
    return $value;
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

function google_api_php_client_autoload($className)
{
  $classPath = explode('_', $className);
  if ($classPath[0] != 'Google') {
    return;
  }
  // Drop 'Google', and maximum class file path depth in this project is 3.
  $classPath = array_slice($classPath, 1, 2);

  $filePath = dirname(__FILE__) . '/' . implode('/', $classPath) . '.php';
  if (file_exists($filePath)) {
    require_once($filePath);
  }
}

spl_autoload_register('google_api_php_client_autoload');
 
/*
 * Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Class to handle batched requests to the Google API service.
 */
class Google_Http_Batch
{
  /** @var string Multipart Boundary. */
  private $boundary;

  /** @var array service requests to be executed. */
  private $requests = array();

  /** @var Google_Client */
  private $client;

  private $expected_classes = array();

  private $base_path;

  public function __construct(Google_Client $client, $boundary = false)
  {
    $this->client = $client;
    $this->base_path = $this->client->getBasePath();
    $this->expected_classes = array();
    $boundary = (false == $boundary) ? mt_rand() : $boundary;
    $this->boundary = str_replace('"', '', $boundary);
  }

  public function add(Google_Http_Request $request, $key = false)
  {
    if (false == $key) {
      $key = mt_rand();
    }

    $this->requests[$key] = $request;
  }

  public function execute()
  {
    $body = '';

    /** @var Google_Http_Request $req */
    foreach ($this->requests as $key => $req) {
      $body .= "--{$this->boundary}\n";
      $body .= $req->toBatchString($key) . "\n";
      $this->expected_classes["response-" . $key] = $req->getExpectedClass();
    }

    $body = rtrim($body);
    $body .= "\n--{$this->boundary}--";

    $url = $this->base_path . '/batch';
    $httpRequest = new Google_Http_Request($url, 'POST');
    $httpRequest->setRequestHeaders(
        array('Content-Type' => 'multipart/mixed; boundary=' . $this->boundary)
    );

    $httpRequest->setPostBody($body);
    $response = $this->client->getIo()->makeRequest($httpRequest);

    return $this->parseResponse($response);
  }

  public function parseResponse(Google_Http_Request $response)
  {
    $contentType = $response->getResponseHeader('content-type');
    $contentType = explode(';', $contentType);
    $boundary = false;
    foreach ($contentType as $part) {
      $part = (explode('=', $part, 2));
      if (isset($part[0]) && 'boundary' == trim($part[0])) {
        $boundary = $part[1];
      }
    }

    $body = $response->getResponseBody();
    if ($body) {
      $body = str_replace("--$boundary--", "--$boundary", $body);
      $parts = explode("--$boundary", $body);
      $responses = array();

      foreach ($parts as $part) {
        $part = trim($part);
        if (!empty($part)) {
          list($metaHeaders, $part) = explode("\r\n\r\n", $part, 2);
          $metaHeaders = $this->client->getIo()->getHttpResponseHeaders($metaHeaders);

          $status = substr($part, 0, strpos($part, "\n"));
          $status = explode(" ", $status);
          $status = $status[1];

          list($partHeaders, $partBody) = $this->client->getIo()->ParseHttpResponse($part, false);
          $response = new Google_Http_Request("");
          $response->setResponseHttpCode($status);
          $response->setResponseHeaders($partHeaders);
          $response->setResponseBody($partBody);

          // Need content id.
          $key = $metaHeaders['content-id'];

          if (isset($this->expected_classes[$key]) &&
              strlen($this->expected_classes[$key]) > 0) {
            $class = $this->expected_classes[$key];
            $response->setExpectedClass($class);
          }

          try {
            $response = Google_Http_REST::decodeHttpResponse($response, $this->client);
            $responses[$key] = $response;
          } catch (Google_Service_Exception $e) {
            // Store the exception as the response, so successful responses
            // can be processed.
            $responses[$key] = $e;
          }
        }
      }

      return $responses;
    }

    return null;
  }
}
 
/*
 * Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Implement the caching directives specified in rfc2616. This
 * implementation is guided by the guidance offered in rfc2616-sec13.
 */
class Google_Http_CacheParser
{
  public static $CACHEABLE_HTTP_METHODS = array('GET', 'HEAD');
  public static $CACHEABLE_STATUS_CODES = array('200', '203', '300', '301');

  /**
   * Check if an HTTP request can be cached by a private local cache.
   *
   * @static
   * @param Google_Http_Request $resp
   * @return bool True if the request is cacheable.
   * False if the request is uncacheable.
   */
  public static function isRequestCacheable(Google_Http_Request $resp)
  {
    $method = $resp->getRequestMethod();
    if (! in_array($method, self::$CACHEABLE_HTTP_METHODS)) {
      return false;
    }

    // Don't cache authorized requests/responses.
    // [rfc2616-14.8] When a shared cache receives a request containing an
    // Authorization field, it MUST NOT return the corresponding response
    // as a reply to any other request...
    if ($resp->getRequestHeader("authorization")) {
      return false;
    }

    return true;
  }

  /**
   * Check if an HTTP response can be cached by a private local cache.
   *
   * @static
   * @param Google_Http_Request $resp
   * @return bool True if the response is cacheable.
   * False if the response is un-cacheable.
   */
  public static function isResponseCacheable(Google_Http_Request $resp)
  {
    // First, check if the HTTP request was cacheable before inspecting the
    // HTTP response.
    if (false == self::isRequestCacheable($resp)) {
      return false;
    }

    $code = $resp->getResponseHttpCode();
    if (! in_array($code, self::$CACHEABLE_STATUS_CODES)) {
      return false;
    }

    // The resource is uncacheable if the resource is already expired and
    // the resource doesn't have an ETag for revalidation.
    $etag = $resp->getResponseHeader("etag");
    if (self::isExpired($resp) && $etag == false) {
      return false;
    }

    // [rfc2616-14.9.2]  If [no-store is] sent in a response, a cache MUST NOT
    // store any part of either this response or the request that elicited it.
    $cacheControl = $resp->getParsedCacheControl();
    if (isset($cacheControl['no-store'])) {
      return false;
    }

    // Pragma: no-cache is an http request directive, but is occasionally
    // used as a response header incorrectly.
    $pragma = $resp->getResponseHeader('pragma');
    if ($pragma == 'no-cache' || strpos($pragma, 'no-cache') !== false) {
      return false;
    }

    // [rfc2616-14.44] Vary: * is extremely difficult to cache. "It implies that
    // a cache cannot determine from the request headers of a subsequent request
    // whether this response is the appropriate representation."
    // Given this, we deem responses with the Vary header as uncacheable.
    $vary = $resp->getResponseHeader('vary');
    if ($vary) {
      return false;
    }

    return true;
  }

  /**
   * @static
   * @param Google_Http_Request $resp
   * @return bool True if the HTTP response is considered to be expired.
   * False if it is considered to be fresh.
   */
  public static function isExpired(Google_Http_Request $resp)
  {
    // HTTP/1.1 clients and caches MUST treat other invalid date formats,
    // especially including the value “0”, as in the past.
    $parsedExpires = false;
    $responseHeaders = $resp->getResponseHeaders();

    if (isset($responseHeaders['expires'])) {
      $rawExpires = $responseHeaders['expires'];
      // Check for a malformed expires header first.
      if (empty($rawExpires) || (is_numeric($rawExpires) && $rawExpires <= 0)) {
        return true;
      }

      // See if we can parse the expires header.
      $parsedExpires = strtotime($rawExpires);
      if (false == $parsedExpires || $parsedExpires <= 0) {
        return true;
      }
    }

    // Calculate the freshness of an http response.
    $freshnessLifetime = false;
    $cacheControl = $resp->getParsedCacheControl();
    if (isset($cacheControl['max-age'])) {
      $freshnessLifetime = $cacheControl['max-age'];
    }

    $rawDate = $resp->getResponseHeader('date');
    $parsedDate = strtotime($rawDate);

    if (empty($rawDate) || false == $parsedDate) {
      // We can't default this to now, as that means future cache reads
      // will always pass with the logic below, so we will require a
      // date be injected if not supplied.
      throw new Google_Exception("All cacheable requests must have creation dates.");
    }

    if (false == $freshnessLifetime && isset($responseHeaders['expires'])) {
      $freshnessLifetime = $parsedExpires - $parsedDate;
    }

    if (false == $freshnessLifetime) {
      return true;
    }

    // Calculate the age of an http response.
    $age = max(0, time() - $parsedDate);
    if (isset($responseHeaders['age'])) {
      $age = max($age, strtotime($responseHeaders['age']));
    }

    return $freshnessLifetime <= $age;
  }

  /**
   * Determine if a cache entry should be revalidated with by the origin.
   *
   * @param Google_Http_Request $response
   * @return bool True if the entry is expired, else return false.
   */
  public static function mustRevalidate(Google_Http_Request $response)
  {
    // [13.3] When a cache has a stale entry that it would like to use as a
    // response to a client's request, it first has to check with the origin
    // server to see if its cached entry is still usable.
    return self::isExpired($response);
  }
}
 
/**
 * Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Manage large file uploads, which may be media but can be any type
 * of sizable data.
 */
class Google_Http_MediaFileUpload
{
  const UPLOAD_MEDIA_TYPE = 'media';
  const UPLOAD_MULTIPART_TYPE = 'multipart';
  const UPLOAD_RESUMABLE_TYPE = 'resumable';

  /** @var string $mimeType */
  private $mimeType;

  /** @var string $data */
  private $data;

  /** @var bool $resumable */
  private $resumable;

  /** @var int $chunkSize */
  private $chunkSize;

  /** @var int $size */
  private $size;

  /** @var string $resumeUri */
  private $resumeUri;

  /** @var int $progress */
  private $progress;

  /** @var Google_Client */
  private $client;

  /** @var Google_Http_Request */
  private $request;

  /** @var string */
  private $boundary;

  /**
   * Result code from last HTTP call
   * @var int
   */
  private $httpResultCode;

  /**
   * @param $mimeType string
   * @param $data string The bytes you want to upload.
   * @param $resumable bool
   * @param bool $chunkSize File will be uploaded in chunks of this many bytes.
   * only used if resumable=True
   */
  public function __construct(
      Google_Client $client,
      Google_Http_Request $request,
      $mimeType,
      $data,
      $resumable = false,
      $chunkSize = false,
      $boundary = false
  ) {
    $this->client = $client;
    $this->request = $request;
    $this->mimeType = $mimeType;
    $this->data = $data;
    $this->size = strlen($this->data);
    $this->resumable = $resumable;
    if (!$chunkSize) {
      $chunkSize = 256 * 1024;
    }
    $this->chunkSize = $chunkSize;
    $this->progress = 0;
    $this->boundary = $boundary;

    // Process Media Request
    $this->process();
  }

  /**
   * Set the size of the file that is being uploaded.
   * @param $size - int file size in bytes
   */
  public function setFileSize($size)
  {
    $this->size = $size;
  }

  /**
   * Return the progress on the upload
   * @return int progress in bytes uploaded.
   */
  public function getProgress()
  {
    return $this->progress;
  }

  /**
   * Return the HTTP result code from the last call made.
   * @return int code
   */
  public function getHttpResultCode()
  {
    return $this->httpResultCode;
  }

  /**
   * Send the next part of the file to upload.
   * @param [$chunk] the next set of bytes to send. If false will used $data passed
   * at construct time.
   */
  public function nextChunk($chunk = false)
  {
    if (false == $this->resumeUri) {
      $this->resumeUri = $this->getResumeUri();
    }

    if (false == $chunk) {
      $chunk = substr($this->data, $this->progress, $this->chunkSize);
    }

    $lastBytePos = $this->progress + strlen($chunk) - 1;
    $headers = array(
      'content-range' => "bytes $this->progress-$lastBytePos/$this->size",
      'content-type' => $this->request->getRequestHeader('content-type'),
      'content-length' => $this->chunkSize,
      'expect' => '',
    );

    $httpRequest = new Google_Http_Request(
        $this->resumeUri,
        'PUT',
        $headers,
        $chunk
    );

    if ($this->client->getClassConfig("Google_Http_Request", "enable_gzip_for_uploads")) {
      $httpRequest->enableGzip();
    } else {
      $httpRequest->disableGzip();
    }

    $response = $this->client->getIo()->makeRequest($httpRequest);
    $response->setExpectedClass($this->request->getExpectedClass());
    $code = $response->getResponseHttpCode();
    $this->httpResultCode = $code;

    if (308 == $code) {
      // Track the amount uploaded.
      $range = explode('-', $response->getResponseHeader('range'));
      $this->progress = $range[1] + 1;

      // Allow for changing upload URLs.
      $location = $response->getResponseHeader('location');
      if ($location) {
        $this->resumeUri = $location;
      }

      // No problems, but upload not complete.
      return false;
    } else {
      return Google_Http_REST::decodeHttpResponse($response, $this->client);
    }
  }

  /**
   * @param $meta
   * @param $params
   * @return array|bool
   * @visible for testing
   */
  private function process()
  {
    $postBody = false;
    $contentType = false;

    $meta = $this->request->getPostBody();
    $meta = is_string($meta) ? json_decode($meta, true) : $meta;

    $uploadType = $this->getUploadType($meta);
    $this->request->setQueryParam('uploadType', $uploadType);
    $this->transformToUploadUrl();
    $mimeType = $this->mimeType ?
        $this->mimeType :
        $this->request->getRequestHeader('content-type');

    if (self::UPLOAD_RESUMABLE_TYPE == $uploadType) {
      $contentType = $mimeType;
      $postBody = is_string($meta) ? $meta : json_encode($meta);
    } else if (self::UPLOAD_MEDIA_TYPE == $uploadType) {
      $contentType = $mimeType;
      $postBody = $this->data;
    } else if (self::UPLOAD_MULTIPART_TYPE == $uploadType) {
      // This is a multipart/related upload.
      $boundary = $this->boundary ? $this->boundary : mt_rand();
      $boundary = str_replace('"', '', $boundary);
      $contentType = 'multipart/related; boundary=' . $boundary;
      $related = "--$boundary\r\n";
      $related .= "Content-Type: application/json; charset=UTF-8\r\n";
      $related .= "\r\n" . json_encode($meta) . "\r\n";
      $related .= "--$boundary\r\n";
      $related .= "Content-Type: $mimeType\r\n";
      $related .= "Content-Transfer-Encoding: base64\r\n";
      $related .= "\r\n" . base64_encode($this->data) . "\r\n";
      $related .= "--$boundary--";
      $postBody = $related;
    }

    $this->request->setPostBody($postBody);

    if (isset($contentType) && $contentType) {
      $contentTypeHeader['content-type'] = $contentType;
      $this->request->setRequestHeaders($contentTypeHeader);
    }
  }

  private function transformToUploadUrl()
  {
    $base = $this->request->getBaseComponent();
    $this->request->setBaseComponent($base . '/upload');
  }

  /**
   * Valid upload types:
   * - resumable (UPLOAD_RESUMABLE_TYPE)
   * - media (UPLOAD_MEDIA_TYPE)
   * - multipart (UPLOAD_MULTIPART_TYPE)
   * @param $meta
   * @return string
   * @visible for testing
   */
  public function getUploadType($meta)
  {
    if ($this->resumable) {
      return self::UPLOAD_RESUMABLE_TYPE;
    }

    if (false == $meta && $this->data) {
      return self::UPLOAD_MEDIA_TYPE;
    }

    return self::UPLOAD_MULTIPART_TYPE;
  }

  private function getResumeUri()
  {
    $result = null;
    $body = $this->request->getPostBody();
    if ($body) {
      $headers = array(
        'content-type' => 'application/json; charset=UTF-8',
        'content-length' => Google_Utils::getStrLen($body),
        'x-upload-content-type' => $this->mimeType,
        'x-upload-content-length' => $this->size,
        'expect' => '',
      );
      $this->request->setRequestHeaders($headers);
    }

    $response = $this->client->getIo()->makeRequest($this->request);
    $location = $response->getResponseHeader('location');
    $code = $response->getResponseHttpCode();

    if (200 == $code && true == $location) {
      return $location;
    }
    $message = $code;
    $body = @json_decode($response->getResponseBody());
    if (!empty( $body->error->errors ) ) {
      $message .= ': ';
      foreach ($body->error->errors as $error) {
        $message .= "{$error->domain}, {$error->message};";
      }
      $message = rtrim($message, ';');
    }

    $error = "Failed to start the resumable upload (HTTP {$message})";
    $this->client->getLogger()->error($error);
    throw new Google_Exception($error);
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * This class implements the RESTful transport of apiServiceRequest()'s
 */
class Google_Http_REST
{
  /**
   * Executes a Google_Http_Request and (if applicable) automatically retries
   * when errors occur.
   *
   * @param Google_Client $client
   * @param Google_Http_Request $req
   * @return array decoded result
   * @throws Google_Service_Exception on server side error (ie: not authenticated,
   *  invalid or malformed post body, invalid url)
   */
  public static function execute(Google_Client $client, Google_Http_Request $req)
  {
    $runner = new Google_Task_Runner(
        $client,
        sprintf('%s %s', $req->getRequestMethod(), $req->getUrl()),
        array(get_class(), 'doExecute'),
        array($client, $req)
    );

    return $runner->run();
  }

  /**
   * Executes a Google_Http_Request
   *
   * @param Google_Client $client
   * @param Google_Http_Request $req
   * @return array decoded result
   * @throws Google_Service_Exception on server side error (ie: not authenticated,
   *  invalid or malformed post body, invalid url)
   */
  public static function doExecute(Google_Client $client, Google_Http_Request $req)
  {
    $httpRequest = $client->getIo()->makeRequest($req);
    $httpRequest->setExpectedClass($req->getExpectedClass());
    return self::decodeHttpResponse($httpRequest, $client);
  }

  /**
   * Decode an HTTP Response.
   * @static
   * @throws Google_Service_Exception
   * @param Google_Http_Request $response The http response to be decoded.
   * @param Google_Client $client
   * @return mixed|null
   */
  public static function decodeHttpResponse($response, Google_Client $client = null)
  {
    $code = $response->getResponseHttpCode();
    $body = $response->getResponseBody();
    $decoded = null;

    if ((intVal($code)) >= 300) {
      $decoded = json_decode($body, true);
      $err = 'Error calling ' . $response->getRequestMethod() . ' ' . $response->getUrl();
      if (isset($decoded['error']) &&
          isset($decoded['error']['message'])  &&
          isset($decoded['error']['code'])) {
        // if we're getting a json encoded error definition, use that instead of the raw response
        // body for improved readability
        $err .= ": ({$decoded['error']['code']}) {$decoded['error']['message']}";
      } else {
        $err .= ": ($code) $body";
      }

      $errors = null;
      // Specific check for APIs which don't return error details, such as Blogger.
      if (isset($decoded['error']) && isset($decoded['error']['errors'])) {
        $errors = $decoded['error']['errors'];
      }

      $map = null;
      if ($client) {
        $client->getLogger()->error(
            $err,
            array('code' => $code, 'errors' => $errors)
        );

        $map = $client->getClassConfig(
            'Google_Service_Exception',
            'retry_map'
        );
      }
      throw new Google_Service_Exception($err, $code, null, $errors, $map);
    }

    // Only attempt to decode the response, if the response code wasn't (204) 'no content'
    if ($code != '204') {
      if ($response->getExpectedRaw()) {
        return $body;
      }
      
      $decoded = json_decode($body, true);
      if ($decoded === null || $decoded === "") {
        $error = "Invalid json in service response: $body";
        if ($client) {
          $client->getLogger()->error($error);
        }
        throw new Google_Service_Exception($error);
      }

      if ($response->getExpectedClass()) {
        $class = $response->getExpectedClass();
        $decoded = new $class($decoded);
      }
    }
    return $decoded;
  }

  /**
   * Parse/expand request parameters and create a fully qualified
   * request uri.
   * @static
   * @param string $servicePath
   * @param string $restPath
   * @param array $params
   * @return string $requestUrl
   */
  public static function createRequestUri($servicePath, $restPath, $params)
  {
    $requestUrl = $servicePath . $restPath;
    $uriTemplateVars = array();
    $queryVars = array();
    foreach ($params as $paramName => $paramSpec) {
      if ($paramSpec['type'] == 'boolean') {
        $paramSpec['value'] = ($paramSpec['value']) ? 'true' : 'false';
      }
      if ($paramSpec['location'] == 'path') {
        $uriTemplateVars[$paramName] = $paramSpec['value'];
      } else if ($paramSpec['location'] == 'query') {
        if (isset($paramSpec['repeated']) && is_array($paramSpec['value'])) {
          foreach ($paramSpec['value'] as $value) {
            $queryVars[] = $paramName . '=' . rawurlencode($value);
          }
        } else {
          $queryVars[] = $paramName . '=' . rawurlencode($paramSpec['value']);
        }
      }
    }

    if (count($uriTemplateVars)) {
      $uriTemplateParser = new Google_Utils_URITemplate();
      $requestUrl = $uriTemplateParser->parse($requestUrl, $uriTemplateVars);
    }

    if (count($queryVars)) {
      $requestUrl .= '?' . implode($queryVars, '&');
    }

    return $requestUrl;
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * HTTP Request to be executed by IO classes. Upon execution, the
 * responseHttpCode, responseHeaders and responseBody will be filled in.
 *
 * @author Chris Chabot <chabotc@google.com>
 * @author Chirag Shah <chirags@google.com>
 *
 */
class Google_Http_Request
{
  const GZIP_UA = " (gzip)";

  private $batchHeaders = array(
    'Content-Type' => 'application/http',
    'Content-Transfer-Encoding' => 'binary',
    'MIME-Version' => '1.0',
  );

  protected $queryParams;
  protected $requestMethod;
  protected $requestHeaders;
  protected $baseComponent = null;
  protected $path;
  protected $postBody;
  protected $userAgent;
  protected $canGzip = null;

  protected $responseHttpCode;
  protected $responseHeaders;
  protected $responseBody;
  
  protected $expectedClass;
  protected $expectedRaw = false;

  public $accessKey;

  public function __construct(
      $url,
      $method = 'GET',
      $headers = array(),
      $postBody = null
  ) {
    $this->setUrl($url);
    $this->setRequestMethod($method);
    $this->setRequestHeaders($headers);
    $this->setPostBody($postBody);
  }

  /**
   * Misc function that returns the base url component of the $url
   * used by the OAuth signing class to calculate the base string
   * @return string The base url component of the $url.
   */
  public function getBaseComponent()
  {
    return $this->baseComponent;
  }
  
  /**
   * Set the base URL that path and query parameters will be added to.
   * @param $baseComponent string
   */
  public function setBaseComponent($baseComponent)
  {
    $this->baseComponent = $baseComponent;
  }
  
  /**
   * Enable support for gzipped responses with this request.
   */
  public function enableGzip()
  {
    $this->setRequestHeaders(array("Accept-Encoding" => "gzip"));
    $this->canGzip = true;
    $this->setUserAgent($this->userAgent);
  }
  
  /**
   * Disable support for gzip responses with this request.
   */
  public function disableGzip()
  {
    if (
        isset($this->requestHeaders['accept-encoding']) &&
        $this->requestHeaders['accept-encoding'] == "gzip"
    ) {
      unset($this->requestHeaders['accept-encoding']);
    }
    $this->canGzip = false;
    $this->userAgent = str_replace(self::GZIP_UA, "", $this->userAgent);
  }
  
  /**
   * Can this request accept a gzip response?
   * @return bool
   */
  public function canGzip()
  {
    return $this->canGzip;
  }

  /**
   * Misc function that returns an array of the query parameters of the current
   * url used by the OAuth signing class to calculate the signature
   * @return array Query parameters in the query string.
   */
  public function getQueryParams()
  {
    return $this->queryParams;
  }

  /** 
   * Set a new query parameter.
   * @param $key - string to set, does not need to be URL encoded
   * @param $value - string to set, does not need to be URL encoded
   */
  public function setQueryParam($key, $value)
  {
    $this->queryParams[$key] = $value;
  }

  /**
   * @return string HTTP Response Code.
   */
  public function getResponseHttpCode()
  {
    return (int) $this->responseHttpCode;
  }

  /**
   * @param int $responseHttpCode HTTP Response Code.
   */
  public function setResponseHttpCode($responseHttpCode)
  {
    $this->responseHttpCode = $responseHttpCode;
  }

  /**
   * @return $responseHeaders (array) HTTP Response Headers.
   */
  public function getResponseHeaders()
  {
    return $this->responseHeaders;
  }

  /**
   * @return string HTTP Response Body
   */
  public function getResponseBody()
  {
    return $this->responseBody;
  }
  
  /**
   * Set the class the response to this request should expect.
   *
   * @param $class string the class name
   */
  public function setExpectedClass($class)
  {
    $this->expectedClass = $class;
  }
  
  /**
   * Retrieve the expected class the response should expect.
   * @return string class name
   */
  public function getExpectedClass()
  {
    return $this->expectedClass;
  }

  /**
   * Enable expected raw response
   */
  public function enableExpectedRaw()
  {
    $this->expectedRaw = true;
  }

  /**
   * Disable expected raw response
   */
  public function disableExpectedRaw()
  {
    $this->expectedRaw = false;
  }

  /**
   * Expected raw response or not.
   * @return boolean expected raw response
   */
  public function getExpectedRaw()
  {
    return $this->expectedRaw;
  }

  /**
   * @param array $headers The HTTP response headers
   * to be normalized.
   */
  public function setResponseHeaders($headers)
  {
    $headers = Google_Utils::normalize($headers);
    if ($this->responseHeaders) {
      $headers = array_merge($this->responseHeaders, $headers);
    }

    $this->responseHeaders = $headers;
  }

  /**
   * @param string $key
   * @return array|boolean Returns the requested HTTP header or
   * false if unavailable.
   */
  public function getResponseHeader($key)
  {
    return isset($this->responseHeaders[$key])
        ? $this->responseHeaders[$key]
        : false;
  }

  /**
   * @param string $responseBody The HTTP response body.
   */
  public function setResponseBody($responseBody)
  {
    $this->responseBody = $responseBody;
  }

  /**
   * @return string $url The request URL.
   */
  public function getUrl()
  {
    return $this->baseComponent . $this->path .
        (count($this->queryParams) ?
            "?" . $this->buildQuery($this->queryParams) :
            '');
  }

  /**
   * @return string $method HTTP Request Method.
   */
  public function getRequestMethod()
  {
    return $this->requestMethod;
  }

  /**
   * @return array $headers HTTP Request Headers.
   */
  public function getRequestHeaders()
  {
    return $this->requestHeaders;
  }

  /**
   * @param string $key
   * @return array|boolean Returns the requested HTTP header or
   * false if unavailable.
   */
  public function getRequestHeader($key)
  {
    return isset($this->requestHeaders[$key])
        ? $this->requestHeaders[$key]
        : false;
  }

  /**
   * @return string $postBody HTTP Request Body.
   */
  public function getPostBody()
  {
    return $this->postBody;
  }

  /**
   * @param string $url the url to set
   */
  public function setUrl($url)
  {
    if (substr($url, 0, 4) != 'http') {
      // Force the path become relative.
      if (substr($url, 0, 1) !== '/') {
        $url = '/' . $url;
      }
    }
    $parts = parse_url($url);
    if (isset($parts['host'])) {
      $this->baseComponent = sprintf(
          "%s%s%s",
          isset($parts['scheme']) ? $parts['scheme'] . "://" : '',
          isset($parts['host']) ? $parts['host'] : '',
          isset($parts['port']) ? ":" . $parts['port'] : ''
      );
    }
    $this->path = isset($parts['path']) ? $parts['path'] : '';
    $this->queryParams = array();
    if (isset($parts['query'])) {
      $this->queryParams = $this->parseQuery($parts['query']);
    }
  }

  /**
   * @param string $method Set he HTTP Method and normalize
   * it to upper-case, as required by HTTP.
   *
   */
  public function setRequestMethod($method)
  {
    $this->requestMethod = strtoupper($method);
  }

  /**
   * @param array $headers The HTTP request headers
   * to be set and normalized.
   */
  public function setRequestHeaders($headers)
  {
    $headers = Google_Utils::normalize($headers);
    if ($this->requestHeaders) {
      $headers = array_merge($this->requestHeaders, $headers);
    }
    $this->requestHeaders = $headers;
  }

  /**
   * @param string $postBody the postBody to set
   */
  public function setPostBody($postBody)
  {
    $this->postBody = $postBody;
  }

  /**
   * Set the User-Agent Header.
   * @param string $userAgent The User-Agent.
   */
  public function setUserAgent($userAgent)
  {
    $this->userAgent = $userAgent;
    if ($this->canGzip) {
      $this->userAgent = $userAgent . self::GZIP_UA;
    }
  }

  /**
   * @return string The User-Agent.
   */
  public function getUserAgent()
  {
    return $this->userAgent;
  }

  /**
   * Returns a cache key depending on if this was an OAuth signed request
   * in which case it will use the non-signed url and access key to make this
   * cache key unique per authenticated user, else use the plain request url
   * @return string The md5 hash of the request cache key.
   */
  public function getCacheKey()
  {
    $key = $this->getUrl();

    if (isset($this->accessKey)) {
      $key .= $this->accessKey;
    }

    if (isset($this->requestHeaders['authorization'])) {
      $key .= $this->requestHeaders['authorization'];
    }

    return md5($key);
  }

  public function getParsedCacheControl()
  {
    $parsed = array();
    $rawCacheControl = $this->getResponseHeader('cache-control');
    if ($rawCacheControl) {
      $rawCacheControl = str_replace(', ', '&', $rawCacheControl);
      parse_str($rawCacheControl, $parsed);
    }

    return $parsed;
  }

  /**
   * @param string $id
   * @return string A string representation of the HTTP Request.
   */
  public function toBatchString($id)
  {
    $str = '';
    $path = parse_url($this->getUrl(), PHP_URL_PATH) . "?" .
        http_build_query($this->queryParams);
    $str .= $this->getRequestMethod() . ' ' . $path . " HTTP/1.1\n";

    foreach ($this->getRequestHeaders() as $key => $val) {
      $str .= $key . ': ' . $val . "\n";
    }

    if ($this->getPostBody()) {
      $str .= "\n";
      $str .= $this->getPostBody();
    }
    
    $headers = '';
    foreach ($this->batchHeaders as $key => $val) {
      $headers .= $key . ': ' . $val . "\n";
    }

    $headers .= "Content-ID: $id\n";
    $str = $headers . "\n" . $str;

    return $str;
  }
  
  /**
   * Our own version of parse_str that allows for multiple variables
   * with the same name. 
   * @param $string - the query string to parse
   */
  private function parseQuery($string)
  {
    $return = array();
    $parts = explode("&", $string);
    foreach ($parts as $part) {
      list($key, $value) = explode('=', $part, 2);
      $value = urldecode($value);
      if (isset($return[$key])) {
        if (!is_array($return[$key])) {
          $return[$key] = array($return[$key]);
        }
        $return[$key][] = $value;
      } else {
        $return[$key] = $value;
      }
    }
    return $return;
  }
  
  /**
   * A version of build query that allows for multiple
   * duplicate keys. 
   * @param $parts array of key value pairs
   */
  private function buildQuery($parts)
  {
    $return = array();
    foreach ($parts as $key => $value) {
      if (is_array($value)) {
        foreach ($value as $v) {
          $return[] = urlencode($key) . "=" . urlencode($v);
        }
      } else {
        $return[] = urlencode($key) . "=" . urlencode($value);
      }
    }
    return implode('&', $return);
  }
  
  /** 
   * If we're POSTing and have no body to send, we can send the query
   * parameters in there, which avoids length issues with longer query
   * params.
   */
  public function maybeMoveParametersToBody()
  {
    if ($this->getRequestMethod() == "POST" && empty($this->postBody)) {
      $this->setRequestHeaders(
          array(
            "content-type" =>
                "application/x-www-form-urlencoded; charset=UTF-8"
          )
      );
      $this->setPostBody($this->buildQuery($this->queryParams));
      $this->queryParams = array();
    }
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Implementation of levels 1-3 of the URI Template spec. 
 * @see http://tools.ietf.org/html/rfc6570
 */
class Google_Utils_URITemplate
{
  const TYPE_MAP = "1";
  const TYPE_LIST = "2";
  const TYPE_SCALAR = "4";

  /**
   * @var $operators array 
   * These are valid at the start of a template block to
   * modify the way in which the variables inside are
   * processed.
   */
  private $operators = array(
      "+" => "reserved",
      "/" => "segments",
      "." => "dotprefix",
      "#" => "fragment",
      ";" => "semicolon",
      "?" => "form",
      "&" => "continuation"
  );

  /**
   * @var reserved array
   * These are the characters which should not be URL encoded in reserved
   * strings.
   */
  private $reserved = array(
      "=", ",", "!", "@", "|", ":", "/", "?", "#",
      "[", "]",'$', "&", "'", "(", ")", "*", "+", ";"
  );
  private $reservedEncoded = array(
    "%3D", "%2C", "%21", "%40", "%7C", "%3A", "%2F", "%3F",
    "%23", "%5B", "%5D", "%24", "%26", "%27", "%28", "%29",
    "%2A", "%2B", "%3B"
  );

  public function parse($string, array $parameters)
  {
    return $this->resolveNextSection($string, $parameters);
  }

  /**
   * This function finds the first matching {...} block and
   * executes the replacement. It then calls itself to find
   * subsequent blocks, if any. 
   */
  private function resolveNextSection($string, $parameters)
  {
    $start = strpos($string, "{");
    if ($start === false) {
      return $string;
    }
    $end = strpos($string, "}");
    if ($end === false) {
      return $string;
    }
    $string = $this->replace($string, $start, $end, $parameters);
    return $this->resolveNextSection($string, $parameters);
  }

  private function replace($string, $start, $end, $parameters)
  {
    // We know a data block will have {} round it, so we can strip that.
    $data = substr($string, $start + 1, $end - $start - 1);

    // If the first character is one of the reserved operators, it effects
    // the processing of the stream.
    if (isset($this->operators[$data[0]])) {
      $op = $this->operators[$data[0]];
      $data = substr($data, 1);
      $prefix = "";
      $prefix_on_missing = false;

      switch ($op) {
        case "reserved":
          // Reserved means certain characters should not be URL encoded
          $data = $this->replaceVars($data, $parameters, ",", null, true);
          break;
        case "fragment":
          // Comma separated with fragment prefix. Bare values only.
          $prefix = "#";
          $prefix_on_missing = true;
          $data = $this->replaceVars($data, $parameters, ",", null, true);
          break;
        case "segments":
          // Slash separated data. Bare values only.
          $prefix = "/";
          $data =$this->replaceVars($data, $parameters, "/");
          break;
        case "dotprefix":
          // Dot separated data. Bare values only.
          $prefix = ".";
          $prefix_on_missing = true;
          $data = $this->replaceVars($data, $parameters, ".");
          break;
        case "semicolon":
          // Semicolon prefixed and separated. Uses the key name
          $prefix = ";";
          $data = $this->replaceVars($data, $parameters, ";", "=", false, true, false);
          break;
        case "form":
          // Standard URL format. Uses the key name
          $prefix = "?";
          $data = $this->replaceVars($data, $parameters, "&", "=");
          break;
        case "continuation":
          // Standard URL, but with leading ampersand. Uses key name.
          $prefix = "&";
          $data = $this->replaceVars($data, $parameters, "&", "=");
          break;
      }

      // Add the initial prefix character if data is valid.
      if ($data || ($data !== false && $prefix_on_missing)) {
        $data = $prefix . $data;
      }

    } else {
      // If no operator we replace with the defaults.
      $data = $this->replaceVars($data, $parameters);
    }
    // This is chops out the {...} and replaces with the new section.
    return substr($string, 0, $start) . $data . substr($string, $end + 1);
  }

  private function replaceVars(
      $section,
      $parameters,
      $sep = ",",
      $combine = null,
      $reserved = false,
      $tag_empty = false,
      $combine_on_empty = true
  ) {
    if (strpos($section, ",") === false) {
      // If we only have a single value, we can immediately process.
      return $this->combine(
          $section,
          $parameters,
          $sep,
          $combine,
          $reserved,
          $tag_empty,
          $combine_on_empty
      );
    } else {
      // If we have multiple values, we need to split and loop over them.
      // Each is treated individually, then glued together with the
      // separator character.
      $vars = explode(",", $section);
      return $this->combineList(
          $vars,
          $sep,
          $parameters,
          $combine,
          $reserved,
          false, // Never emit empty strings in multi-param replacements
          $combine_on_empty
      );
    }
  }
 
  public function combine(
      $key,
      $parameters,
      $sep,
      $combine,
      $reserved,
      $tag_empty,
      $combine_on_empty
  ) {
    $length = false;
    $explode = false;
    $skip_final_combine = false;
    $value = false;

    // Check for length restriction.
    if (strpos($key, ":") !== false) {
      list($key, $length) = explode(":", $key);
    }
    
    // Check for explode parameter.
    if ($key[strlen($key) - 1] == "*") {
      $explode = true;
      $key = substr($key, 0, -1);
      $skip_final_combine = true;
    }
    
    // Define the list separator.
    $list_sep = $explode ? $sep : ",";
    
    if (isset($parameters[$key])) {
      $data_type = $this->getDataType($parameters[$key]);
      switch($data_type) {
        case self::TYPE_SCALAR:
          $value = $this->getValue($parameters[$key], $length);
          break;
        case self::TYPE_LIST:
          $values = array();
          foreach ($parameters[$key] as $pkey => $pvalue) {
            $pvalue = $this->getValue($pvalue, $length);
            if ($combine && $explode) {
              $values[$pkey] = $key . $combine . $pvalue;
            } else {
              $values[$pkey] = $pvalue;
            }
          }
          $value = implode($list_sep, $values);
          if ($value == '') {
            return '';
          }
          break;
        case self::TYPE_MAP:
          $values = array();
          foreach ($parameters[$key] as $pkey => $pvalue) {
            $pvalue = $this->getValue($pvalue, $length);
            if ($explode) {
              $pkey = $this->getValue($pkey, $length);
              $values[] = $pkey . "=" . $pvalue; // Explode triggers = combine.
            } else {
              $values[] = $pkey;
              $values[] = $pvalue;
            }
          }
          $value = implode($list_sep, $values);
          if ($value == '') {
            return false;
          }
          break;
      }
    } else if ($tag_empty) {
      // If we are just indicating empty values with their key name, return that.
      return $key;
    } else {
      // Otherwise we can skip this variable due to not being defined.
      return false;
    }

    if ($reserved) {
      $value = str_replace($this->reservedEncoded, $this->reserved, $value);
    }

    // If we do not need to include the key name, we just return the raw
    // value.
    if (!$combine || $skip_final_combine) {
      return $value;
    }
        
    // Else we combine the key name: foo=bar, if value is not the empty string.
    return $key . ($value != '' || $combine_on_empty ? $combine . $value : '');
  }
  
  /**
   * Return the type of a passed in value
   */
  private function getDataType($data)
  {
    if (is_array($data)) {
      reset($data);
      if (key($data) !== 0) {
        return self::TYPE_MAP;
      }
      return self::TYPE_LIST;
    }
    return self::TYPE_SCALAR;
  }
  
  /**
   * Utility function that merges multiple combine calls
   * for multi-key templates.
   */
  private function combineList(
      $vars,
      $sep,
      $parameters,
      $combine,
      $reserved,
      $tag_empty,
      $combine_on_empty
  ) {
    $ret = array();
    foreach ($vars as $var) {
      $response = $this->combine(
          $var,
          $parameters,
          $sep,
          $combine,
          $reserved,
          $tag_empty,
          $combine_on_empty
      );
      if ($response === false) {
        continue;
      }
      $ret[] = $response;
    }
    return implode($sep, $ret);
  }
  
  /**
   * Utility function to encode and trim values
   */
  private function getValue($value, $length)
  {
    if ($length) {
      $value = substr($value, 0, $length);
    }
    $value = rawurlencode($value);
    return $value;
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Abstract logging class based on the PSR-3 standard.
 *
 * NOTE: We don't implement `Psr\Log\LoggerInterface` because we need to
 * maintain PHP 5.2 support.
 *
 * @see https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-3-logger-interface.md
 */
abstract class Google_Logger_Abstract
{
  /**
   * Default log format
   */
  const DEFAULT_LOG_FORMAT = "[%datetime%] %level%: %message% %context%\n";
  /**
   * Default date format
   *
   * Example: 16/Nov/2014:03:26:16 -0500
   */
  const DEFAULT_DATE_FORMAT = 'd/M/Y:H:i:s O';

  /**
   * System is unusable
   */
  const EMERGENCY = 'emergency';
  /**
   * Action must be taken immediately
   *
   * Example: Entire website down, database unavailable, etc. This should
   * trigger the SMS alerts and wake you up.
   */
  const ALERT = 'alert';
  /**
   * Critical conditions
   *
   * Example: Application component unavailable, unexpected exception.
   */
  const CRITICAL = 'critical';
  /**
   * Runtime errors that do not require immediate action but should typically
   * be logged and monitored.
   */
  const ERROR = 'error';
  /**
   * Exceptional occurrences that are not errors.
   *
   * Example: Use of deprecated APIs, poor use of an API, undesirable things
   * that are not necessarily wrong.
   */
  const WARNING = 'warning';
  /**
   * Normal but significant events.
   */
  const NOTICE = 'notice';
  /**
   * Interesting events.
   *
   * Example: User logs in, SQL logs.
   */
  const INFO = 'info';
  /**
   * Detailed debug information.
   */
  const DEBUG = 'debug';

  /**
   * @var array $levels Logging levels
   */
  protected static $levels = array(
      self::EMERGENCY  => 600,
      self::ALERT => 550,
      self::CRITICAL => 500,
      self::ERROR => 400,
      self::WARNING => 300,
      self::NOTICE => 250,
      self::INFO => 200,
      self::DEBUG => 100,
  );

  /**
   * @var integer $level The minimum logging level
   */
  protected $level = self::DEBUG;

  /**
   * @var string $logFormat The current log format
   */
  protected $logFormat = self::DEFAULT_LOG_FORMAT;
  /**
   * @var string $dateFormat The current date format
   */
  protected $dateFormat = self::DEFAULT_DATE_FORMAT;

  /**
   * @var boolean $allowNewLines If newlines are allowed
   */
  protected $allowNewLines = false;

  /**
   * @param Google_Client $client  The current Google client
   */
  public function __construct(Google_Client $client)
  {
    $this->setLevel(
        $client->getClassConfig('Google_Logger_Abstract', 'level')
    );

    $format = $client->getClassConfig('Google_Logger_Abstract', 'log_format');
    $this->logFormat = $format ? $format : self::DEFAULT_LOG_FORMAT;

    $format = $client->getClassConfig('Google_Logger_Abstract', 'date_format');
    $this->dateFormat = $format ? $format : self::DEFAULT_DATE_FORMAT;

    $this->allowNewLines = (bool) $client->getClassConfig(
        'Google_Logger_Abstract',
        'allow_newlines'
    );
  }

  /**
   * Sets the minimum logging level that this logger handles.
   *
   * @param integer $level
   */
  public function setLevel($level)
  {
    $this->level = $this->normalizeLevel($level);
  }

  /**
   * Checks if the logger should handle messages at the provided level.
   *
   * @param  integer $level
   * @return boolean
   */
  public function shouldHandle($level)
  {
    return $this->normalizeLevel($level) >= $this->level;
  }

  /**
   * System is unusable.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function emergency($message, array $context = array())
  {
    $this->log(self::EMERGENCY, $message, $context);
  }

  /**
   * Action must be taken immediately.
   *
   * Example: Entire website down, database unavailable, etc. This should
   * trigger the SMS alerts and wake you up.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function alert($message, array $context = array())
  {
    $this->log(self::ALERT, $message, $context);
  }

  /**
   * Critical conditions.
   *
   * Example: Application component unavailable, unexpected exception.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function critical($message, array $context = array())
  {
    $this->log(self::CRITICAL, $message, $context);
  }

  /**
   * Runtime errors that do not require immediate action but should typically
   * be logged and monitored.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function error($message, array $context = array())
  {
    $this->log(self::ERROR, $message, $context);
  }

  /**
   * Exceptional occurrences that are not errors.
   *
   * Example: Use of deprecated APIs, poor use of an API, undesirable things
   * that are not necessarily wrong.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function warning($message, array $context = array())
  {
    $this->log(self::WARNING, $message, $context);
  }

  /**
   * Normal but significant events.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function notice($message, array $context = array())
  {
    $this->log(self::NOTICE, $message, $context);
  }

  /**
   * Interesting events.
   *
   * Example: User logs in, SQL logs.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function info($message, array $context = array())
  {
    $this->log(self::INFO, $message, $context);
  }

  /**
   * Detailed debug information.
   *
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function debug($message, array $context = array())
  {
    $this->log(self::DEBUG, $message, $context);
  }

  /**
   * Logs with an arbitrary level.
   *
   * @param mixed $level    The log level
   * @param string $message The log message
   * @param array $context  The log context
   */
  public function log($level, $message, array $context = array())
  {
    if (!$this->shouldHandle($level)) {
      return false;
    }

    $levelName = is_int($level) ? array_search($level, self::$levels) : $level;
    $message = $this->interpolate(
        array(
            'message' => $message,
            'context' => $context,
            'level' => strtoupper($levelName),
            'datetime' => new DateTime(),
        )
    );

    $this->write($message);
  }

  /**
   * Interpolates log variables into the defined log format.
   *
   * @param  array $variables The log variables.
   * @return string
   */
  protected function interpolate(array $variables = array())
  {
    $template = $this->logFormat;

    if (!$variables['context']) {
      $template = str_replace('%context%', '', $template);
      unset($variables['context']);
    } else {
      $this->reverseJsonInContext($variables['context']);
    }

    foreach ($variables as $key => $value) {
      if (strpos($template, '%'. $key .'%') !== false) {
        $template = str_replace(
            '%' . $key . '%',
            $this->export($value),
            $template
        );
      }
    }

    return $template;
  }

  /**
   * Reverses JSON encoded PHP arrays and objects so that they log better.
   *
   * @param array $context The log context
   */
  protected function reverseJsonInContext(array &$context)
  {
    if (!$context) {
      return;
    }

    foreach ($context as $key => $val) {
      if (!$val || !is_string($val) || !($val[0] == '{' || $val[0] == '[')) {
        continue;
      }

      $json = @json_decode($val);
      if (is_object($json) || is_array($json)) {
        $context[$key] = $json;
      }
    }
  }

  /**
   * Exports a PHP value for logging to a string.
   *
   * @param mixed $value The value to
   */
  protected function export($value)
  {
    if (is_string($value)) {
      if ($this->allowNewLines) {
        return $value;
      }

      return preg_replace('/[\r\n]+/', ' ', $value);
    }

    if (is_resource($value)) {
      return sprintf(
          'resource(%d) of type (%s)',
          $value,
          get_resource_type($value)
      );
    }

    if ($value instanceof DateTime) {
      return $value->format($this->dateFormat);
    }

    if (version_compare(PHP_VERSION, '5.4.0', '>=')) {
      $options = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;

      if ($this->allowNewLines) {
        $options |= JSON_PRETTY_PRINT;
      }

      return @json_encode($value, $options);
    }

    return str_replace('\\/', '/', @json_encode($value));
  }

  /**
   * Converts a given log level to the integer form.
   *
   * @param  mixed $level   The logging level
   * @return integer $level The normalized level
   * @throws Google_Logger_Exception If $level is invalid
   */
  protected function normalizeLevel($level)
  {
    if (is_int($level) && array_search($level, self::$levels) !== false) {
      return $level;
    }

    if (is_string($level) && isset(self::$levels[$level])) {
      return self::$levels[$level];
    }

    throw new Google_Logger_Exception(
        sprintf("Unknown LogLevel: '%s'", $level)
    );
  }

  /**
   * Writes a message to the current log implementation.
   *
   * @param string $message The message
   */
  abstract protected function write($message);
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_Logger_Exception extends Google_Exception
{
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * File logging class based on the PSR-3 standard.
 *
 * This logger writes to a PHP stream resource.
 */
class Google_Logger_File extends Google_Logger_Abstract
{
  /**
   * @var string|resource $file Where logs are written
   */
  private $file;
  /**
   * @var integer $mode The mode to use if the log file needs to be created
   */
  private $mode = 0640;
  /**
   * @var boolean $lock If a lock should be attempted before writing to the log
   */
  private $lock = false;

  /**
   * @var integer $trappedErrorNumber Trapped error number
   */
  private $trappedErrorNumber;
  /**
   * @var string $trappedErrorString Trapped error string
   */
  private $trappedErrorString;

  /**
   * {@inheritdoc}
   */
  public function __construct(Google_Client $client)
  {
    parent::__construct($client);

    $file = $client->getClassConfig('Google_Logger_File', 'file');
    if (!is_string($file) && !is_resource($file)) {
      throw new Google_Logger_Exception(
          'File logger requires a filename or a valid file pointer'
      );
    }

    $mode = $client->getClassConfig('Google_Logger_File', 'mode');
    if (!$mode) {
      $this->mode = $mode;
    }

    $this->lock = (bool) $client->getClassConfig('Google_Logger_File', 'lock');
    $this->file = $file;
  }

  /**
   * {@inheritdoc}
   */
  protected function write($message)
  {
    if (is_string($this->file)) {
      $this->open();
    } elseif (!is_resource($this->file)) {
      throw new Google_Logger_Exception('File pointer is no longer available');
    }

    if ($this->lock) {
      flock($this->file, LOCK_EX);
    }

    fwrite($this->file, (string) $message);

    if ($this->lock) {
      flock($this->file, LOCK_UN);
    }
  }

  /**
   * Opens the log for writing.
   *
   * @return resource
   */
  private function open()
  {
    // Used for trapping `fopen()` errors.
    $this->trappedErrorNumber = null;
    $this->trappedErrorString = null;

    $old = set_error_handler(array($this, 'trapError'));

    $needsChmod = !file_exists($this->file);
    $fh = fopen($this->file, 'a');

    restore_error_handler();

    // Handles trapped `fopen()` errors.
    if ($this->trappedErrorNumber) {
      throw new Google_Logger_Exception(
          sprintf(
              "Logger Error: '%s'",
              $this->trappedErrorString
          ),
          $this->trappedErrorNumber
      );
    }

    if ($needsChmod) {
      @chmod($this->file, $this->mode & ~umask());
    }

    return $this->file = $fh;
  }

  /**
   * Closes the log stream resource.
   */
  private function close()
  {
    if (is_resource($this->file)) {
      fclose($this->file);
    }
  }

  /**
   * Traps `fopen()` errors.
   *
   * @param integer $errno The error number
   * @param string $errstr The error string
   */
  private function trapError($errno, $errstr)
  {
    $this->trappedErrorNumber = $errno;
    $this->trappedErrorString = $errstr;
  }

  public function __destruct()
  {
    $this->close();
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Null logger based on the PSR-3 standard.
 *
 * This logger simply discards all messages.
 */
class Google_Logger_Null extends Google_Logger_Abstract
{
  /**
   * {@inheritdoc}
   */
  public function shouldHandle($level)
  {
    return false;
  }

  /**
   * {@inheritdoc}
   */
  protected function write($message, array $context = array())
  {
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Psr logging class based on the PSR-3 standard.
 *
 * This logger will delegate all logging to a PSR-3 compatible logger specified
 * with the `Google_Logger_Psr::setLogger()` method.
 */
class Google_Logger_Psr extends Google_Logger_Abstract
{
  /**
   * @param Psr\Log\LoggerInterface $logger The PSR-3 logger
   */
  private $logger;

  /**
   * @param Google_Client $client           The current Google client
   * @param Psr\Log\LoggerInterface $logger PSR-3 logger where logging will be delegated.
   */
  public function __construct(Google_Client $client, /*Psr\Log\LoggerInterface*/ $logger = null)
  {
    parent::__construct($client);

    if ($logger) {
      $this->setLogger($logger);
    }
  }

  /**
   * Sets the PSR-3 logger where logging will be delegated.
   *
   * NOTE: The `$logger` should technically implement
   * `Psr\Log\LoggerInterface`, but we don't explicitly require this so that
   * we can be compatible with PHP 5.2.
   *
   * @param Psr\Log\LoggerInterface $logger The PSR-3 logger
   */
  public function setLogger(/*Psr\Log\LoggerInterface*/ $logger)
  {
    $this->logger = $logger;
  }

  /**
   * {@inheritdoc}
   */
  public function shouldHandle($level)
  {
    return isset($this->logger) && parent::shouldHandle($level);
  }

  /**
   * {@inheritdoc}
   */
  public function log($level, $message, array $context = array())
  {
    if (!$this->shouldHandle($level)) {
      return false;
    }

    if ($context) {
      $this->reverseJsonInContext($context);
    }

    $levelName = is_int($level) ? array_search($level, self::$levels) : $level;
    $this->logger->log($levelName, $message, $context);
  }

  /**
   * {@inheritdoc}
   */
  protected function write($message, array $context = array())
  {
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Abstract class for the Authentication in the API client
 * @author Chris Chabot <chabotc@google.com>
 *
 */
abstract class Google_Auth_Abstract
{
  /**
   * An utility function that first calls $this->auth->sign($request) and then
   * executes makeRequest() on that signed request. Used for when a request
   * should be authenticated
   * @param Google_Http_Request $request
   * @return Google_Http_Request $request
   */
  abstract public function authenticatedRequest(Google_Http_Request $request);
  abstract public function sign(Google_Http_Request $request);
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * WARNING - this class depends on the Google App Engine PHP library
 * which is 5.3 and above only, so if you include this in a PHP 5.2
 * setup or one without 5.3 things will blow up.
 */
use google\appengine\api\app_identity\AppIdentityService;

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Authentication via the Google App Engine App Identity service.
 */
class Google_Auth_AppIdentity extends Google_Auth_Abstract
{
  const CACHE_PREFIX = "Google_Auth_AppIdentity::";
  private $key = null;
  private $client;
  private $token = false;
  private $tokenScopes = false;

  public function __construct(Google_Client $client, $config = null)
  {
    $this->client = $client;
  }

  /**
   * Retrieve an access token for the scopes supplied.
   */
  public function authenticateForScope($scopes)
  {
    if ($this->token && $this->tokenScopes == $scopes) {
      return $this->token;
    }

    $cacheKey = self::CACHE_PREFIX;
    if (is_string($scopes)) {
      $cacheKey .= $scopes;
    } else if (is_array($scopes)) {
      $cacheKey .= implode(":", $scopes);
    }

    $this->token = $this->client->getCache()->get($cacheKey);
    if (!$this->token) {
      $this->retrieveToken($scopes, $cacheKey);
    } else if ($this->token['expiration_time'] < time()) {
      $this->client->getCache()->delete($cacheKey);
      $this->retrieveToken($scopes, $cacheKey);
    }

    $this->tokenScopes = $scopes;
    return $this->token;
  }

  /**
   * Retrieve a new access token and store it in cache
   * @param mixed $scopes
   * @param string $cacheKey
   */
  private function retrieveToken($scopes, $cacheKey)
  {
    $this->token = AppIdentityService::getAccessToken($scopes);
    if ($this->token) {
      $this->client->getCache()->set(
          $cacheKey,
          $this->token
      );
    }
  }

  /**
   * Perform an authenticated / signed apiHttpRequest.
   * This function takes the apiHttpRequest, calls apiAuth->sign on it
   * (which can modify the request in what ever way fits the auth mechanism)
   * and then calls apiCurlIO::makeRequest on the signed request
   *
   * @param Google_Http_Request $request
   * @return Google_Http_Request The resulting HTTP response including the
   * responseHttpCode, responseHeaders and responseBody.
   */
  public function authenticatedRequest(Google_Http_Request $request)
  {
    $request = $this->sign($request);
    return $this->client->getIo()->makeRequest($request);
  }

  public function sign(Google_Http_Request $request)
  {
    if (!$this->token) {
      // No token, so nothing to do.
      return $request;
    }

    $this->client->getLogger()->debug('App Identity authentication');

    // Add the OAuth2 header to the request
    $request->setRequestHeaders(
        array('Authorization' => 'Bearer ' . $this->token['access_token'])
    );

    return $request;
  }
}
 
/*
 * Copyright 2012 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Credentials object used for OAuth 2.0 Signed JWT assertion grants.
 */
class Google_Auth_AssertionCredentials
{
  const MAX_TOKEN_LIFETIME_SECS = 3600;

  public $serviceAccountName;
  public $scopes;
  public $privateKey;
  public $privateKeyPassword;
  public $assertionType;
  public $sub;
  /**
   * @deprecated
   * @link http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-06
   */
  public $prn;
  private $useCache;

  /**
   * @param $serviceAccountName
   * @param $scopes array List of scopes
   * @param $privateKey
   * @param string $privateKeyPassword
   * @param string $assertionType
   * @param bool|string $sub The email address of the user for which the
   *              application is requesting delegated access.
   * @param bool useCache Whether to generate a cache key and allow
   *              automatic caching of the generated token.
   */
  public function __construct(
      $serviceAccountName,
      $scopes,
      $privateKey,
      $privateKeyPassword = 'notasecret',
      $assertionType = 'http://oauth.net/grant_type/jwt/1.0/bearer',
      $sub = false,
      $useCache = true
  ) {
    $this->serviceAccountName = $serviceAccountName;
    $this->scopes = is_string($scopes) ? $scopes : implode(' ', $scopes);
    $this->privateKey = $privateKey;
    $this->privateKeyPassword = $privateKeyPassword;
    $this->assertionType = $assertionType;
    $this->sub = $sub;
    $this->prn = $sub;
    $this->useCache = $useCache;
  }
  
  /**
   * Generate a unique key to represent this credential.
   * @return string
   */
  public function getCacheKey()
  {
    if (!$this->useCache) {
      return false;
    }
    $h = $this->sub;
    $h .= $this->assertionType;
    $h .= $this->privateKey;
    $h .= $this->scopes;
    $h .= $this->serviceAccountName;
    return md5($h);
  }

  public function generateAssertion()
  {
    $now = time();

    $jwtParams = array(
          'aud' => Google_Auth_OAuth2::OAUTH2_TOKEN_URI,
          'scope' => $this->scopes,
          'iat' => $now,
          'exp' => $now + self::MAX_TOKEN_LIFETIME_SECS,
          'iss' => $this->serviceAccountName,
    );

    if ($this->sub !== false) {
      $jwtParams['sub'] = $this->sub;
    } else if ($this->prn !== false) {
      $jwtParams['prn'] = $this->prn;
    }

    return $this->makeSignedJwt($jwtParams);
  }

  /**
   * Creates a signed JWT.
   * @param array $payload
   * @return string The signed JWT.
   */
  private function makeSignedJwt($payload)
  {
    $header = array('typ' => 'JWT', 'alg' => 'RS256');

    $payload = json_encode($payload);
    // Handle some overzealous escaping in PHP json that seemed to cause some errors
    // with claimsets.
    $payload = str_replace('\/', '/', $payload);

    $segments = array(
      Google_Utils::urlSafeB64Encode(json_encode($header)),
      Google_Utils::urlSafeB64Encode($payload)
    );

    $signingInput = implode('.', $segments);
    $signer = new Google_Signer_P12($this->privateKey, $this->privateKeyPassword);
    $signature = $signer->sign($signingInput);
    $segments[] = Google_Utils::urlSafeB64Encode($signature);

    return implode(".", $segments);
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Authentication via built-in Compute Engine service accounts.
 * The instance must be pre-configured with a service account
 * and the appropriate scopes.
 * @author Jonathan Parrott <jon.wayne.parrott@gmail.com>
 */
class Google_Auth_ComputeEngine extends Google_Auth_Abstract
{
  const METADATA_AUTH_URL =
      'http://metadata/computeMetadata/v1/instance/service-accounts/default/token';
  private $client;
  private $token;

  public function __construct(Google_Client $client, $config = null)
  {
    $this->client = $client;
  }

  /**
   * Perform an authenticated / signed apiHttpRequest.
   * This function takes the apiHttpRequest, calls apiAuth->sign on it
   * (which can modify the request in what ever way fits the auth mechanism)
   * and then calls apiCurlIO::makeRequest on the signed request
   *
   * @param Google_Http_Request $request
   * @return Google_Http_Request The resulting HTTP response including the
   * responseHttpCode, responseHeaders and responseBody.
   */
  public function authenticatedRequest(Google_Http_Request $request)
  {
    $request = $this->sign($request);
    return $this->client->getIo()->makeRequest($request);
  }

  /**
   * @param string $token
   * @throws Google_Auth_Exception
   */
  public function setAccessToken($token)
  {
    $token = json_decode($token, true);
    if ($token == null) {
      throw new Google_Auth_Exception('Could not json decode the token');
    }
    if (! isset($token['access_token'])) {
      throw new Google_Auth_Exception("Invalid token format");
    }
    $token['created'] = time();
    $this->token = $token;
  }

  public function getAccessToken()
  {
    return json_encode($this->token);
  }

  /**
   * Acquires a new access token from the compute engine metadata server.
   * @throws Google_Auth_Exception
   */
  public function acquireAccessToken()
  {
    $request = new Google_Http_Request(
        self::METADATA_AUTH_URL,
        'GET',
        array(
          'Metadata-Flavor' => 'Google'
        )
    );
    $request->disableGzip();
    $response = $this->client->getIo()->makeRequest($request);

    if ($response->getResponseHttpCode() == 200) {
      $this->setAccessToken($response->getResponseBody());
      $this->token['created'] = time();
      return $this->getAccessToken();
    } else {
      throw new Google_Auth_Exception(
          sprintf(
              "Error fetching service account access token, message: '%s'",
              $response->getResponseBody()
          ),
          $response->getResponseHttpCode()
      );
    }
  }

  /**
   * Include an accessToken in a given apiHttpRequest.
   * @param Google_Http_Request $request
   * @return Google_Http_Request
   * @throws Google_Auth_Exception
   */
  public function sign(Google_Http_Request $request)
  {
    if ($this->isAccessTokenExpired()) {
      $this->acquireAccessToken();
    }

    $this->client->getLogger()->debug('Compute engine service account authentication');

    $request->setRequestHeaders(
        array('Authorization' => 'Bearer ' . $this->token['access_token'])
    );

    return $request;
  }

  /**
   * Returns if the access_token is expired.
   * @return bool Returns True if the access_token is expired.
   */
  public function isAccessTokenExpired()
  {
    if (!$this->token || !isset($this->token['created'])) {
      return true;
    }

    // If the token is set to expire in the next 30 seconds.
    $expired = ($this->token['created']
        + ($this->token['expires_in'] - 30)) < time();

    return $expired;
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_Auth_Exception extends Google_Exception
{
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Class to hold information about an authenticated login.
 *
 * @author Brian Eaton <beaton@google.com>
 */
class Google_Auth_LoginTicket
{
  const USER_ATTR = "sub";

  // Information from id token envelope.
  private $envelope;

  // Information from id token payload.
  private $payload;

  /**
   * Creates a user based on the supplied token.
   *
   * @param string $envelope Header from a verified authentication token.
   * @param string $payload Information from a verified authentication token.
   */
  public function __construct($envelope, $payload)
  {
    $this->envelope = $envelope;
    $this->payload = $payload;
  }

  /**
   * Returns the numeric identifier for the user.
   * @throws Google_Auth_Exception
   * @return
   */
  public function getUserId()
  {
    if (array_key_exists(self::USER_ATTR, $this->payload)) {
      return $this->payload[self::USER_ATTR];
    }
    throw new Google_Auth_Exception("No user_id in token");
  }

  /**
   * Returns attributes from the login ticket.  This can contain
   * various information about the user session.
   * @return array
   */
  public function getAttributes()
  {
    return array("envelope" => $this->envelope, "payload" => $this->payload);
  }
}
 
/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Authentication class that deals with the OAuth 2 web-server authentication flow
 *
 */
class Google_Auth_OAuth2 extends Google_Auth_Abstract
{
  const OAUTH2_REVOKE_URI = 'https://accounts.google.com/o/oauth2/revoke';
  const OAUTH2_TOKEN_URI = 'https://accounts.google.com/o/oauth2/token';
  const OAUTH2_AUTH_URL = 'https://accounts.google.com/o/oauth2/auth';
  const CLOCK_SKEW_SECS = 300; // five minutes in seconds
  const AUTH_TOKEN_LIFETIME_SECS = 300; // five minutes in seconds
  const MAX_TOKEN_LIFETIME_SECS = 86400; // one day in seconds
  const OAUTH2_ISSUER = 'accounts.google.com';

  /** @var Google_Auth_AssertionCredentials $assertionCredentials */
  private $assertionCredentials;

  /**
   * @var string The state parameters for CSRF and other forgery protection.
   */
  private $state;

  /**
   * @var array The token bundle.
   */
  private $token = array();

  /**
   * @var Google_Client the base client
   */
  private $client;

  /**
   * Instantiates the class, but does not initiate the login flow, leaving it
   * to the discretion of the caller.
   */
  public function __construct(Google_Client $client)
  {
    $this->client = $client;
  }

  /**
   * Perform an authenticated / signed apiHttpRequest.
   * This function takes the apiHttpRequest, calls apiAuth->sign on it
   * (which can modify the request in what ever way fits the auth mechanism)
   * and then calls apiCurlIO::makeRequest on the signed request
   *
   * @param Google_Http_Request $request
   * @return Google_Http_Request The resulting HTTP response including the
   * responseHttpCode, responseHeaders and responseBody.
   */
  public function authenticatedRequest(Google_Http_Request $request)
  {
    $request = $this->sign($request);
    return $this->client->getIo()->makeRequest($request);
  }

  /**
   * @param string $code
   * @throws Google_Auth_Exception
   * @return string
   */
  public function authenticate($code)
  {
    if (strlen($code) == 0) {
      throw new Google_Auth_Exception("Invalid code");
    }

    // We got here from the redirect from a successful authorization grant,
    // fetch the access token
    $request = new Google_Http_Request(
        self::OAUTH2_TOKEN_URI,
        'POST',
        array(),
        array(
          'code' => $code,
          'grant_type' => 'authorization_code',
          'redirect_uri' => $this->client->getClassConfig($this, 'redirect_uri'),
          'client_id' => $this->client->getClassConfig($this, 'client_id'),
          'client_secret' => $this->client->getClassConfig($this, 'client_secret')
        )
    );
    $request->disableGzip();
    $response = $this->client->getIo()->makeRequest($request);

    if ($response->getResponseHttpCode() == 200) {
      $this->setAccessToken($response->getResponseBody());
      $this->token['created'] = time();
      return $this->getAccessToken();
    } else {
      $decodedResponse = json_decode($response->getResponseBody(), true);
      if ($decodedResponse != null && $decodedResponse['error']) {
        $errorText = $decodedResponse['error'];
        if (isset($decodedResponse['error_description'])) {
          $errorText .= ": " . $decodedResponse['error_description'];
        }
      }
      throw new Google_Auth_Exception(
          sprintf(
              "Error fetching OAuth2 access token, message: '%s'",
              $errorText
          ),
          $response->getResponseHttpCode()
      );
    }
  }

  /**
   * Create a URL to obtain user authorization.
   * The authorization endpoint allows the user to first
   * authenticate, and then grant/deny the access request.
   * @param string $scope The scope is expressed as a list of space-delimited strings.
   * @return string
   */
  public function createAuthUrl($scope)
  {
    $params = array(
        'response_type' => 'code',
        'redirect_uri' => $this->client->getClassConfig($this, 'redirect_uri'),
        'client_id' => $this->client->getClassConfig($this, 'client_id'),
        'scope' => $scope,
        'access_type' => $this->client->getClassConfig($this, 'access_type'),
    );

    // Prefer prompt to approval prompt.
    if ($this->client->getClassConfig($this, 'prompt')) {
      $params = $this->maybeAddParam($params, 'prompt');
    } else {
      $params = $this->maybeAddParam($params, 'approval_prompt');
    }
    $params = $this->maybeAddParam($params, 'login_hint');
    $params = $this->maybeAddParam($params, 'hd');
    $params = $this->maybeAddParam($params, 'openid.realm');
    $params = $this->maybeAddParam($params, 'include_granted_scopes');

    // If the list of scopes contains plus.login, add request_visible_actions
    // to auth URL.
    $rva = $this->client->getClassConfig($this, 'request_visible_actions');
    if (strpos($scope, 'plus.login') && strlen($rva) > 0) {
        $params['request_visible_actions'] = $rva;
    }

    if (isset($this->state)) {
      $params['state'] = $this->state;
    }

    return self::OAUTH2_AUTH_URL . "?" . http_build_query($params, '', '&');
  }

  /**
   * @param string $token
   * @throws Google_Auth_Exception
   */
  public function setAccessToken($token)
  {
    $token = json_decode($token, true);
    if ($token == null) {
      throw new Google_Auth_Exception('Could not json decode the token');
    }
    if (! isset($token['access_token'])) {
      throw new Google_Auth_Exception("Invalid token format");
    }
    $this->token = $token;
  }

  public function getAccessToken()
  {
    return json_encode($this->token);
  }

  public function getRefreshToken()
  {
    if (array_key_exists('refresh_token', $this->token)) {
      return $this->token['refresh_token'];
    } else {
      return null;
    }
  }

  public function setState($state)
  {
    $this->state = $state;
  }

  public function setAssertionCredentials(Google_Auth_AssertionCredentials $creds)
  {
    $this->assertionCredentials = $creds;
  }

  /**
   * Include an accessToken in a given apiHttpRequest.
   * @param Google_Http_Request $request
   * @return Google_Http_Request
   * @throws Google_Auth_Exception
   */
  public function sign(Google_Http_Request $request)
  {
    // add the developer key to the request before signing it
    if ($this->client->getClassConfig($this, 'developer_key')) {
      $request->setQueryParam('key', $this->client->getClassConfig($this, 'developer_key'));
    }

    // Cannot sign the request without an OAuth access token.
    if (null == $this->token && null == $this->assertionCredentials) {
      return $request;
    }

    // Check if the token is set to expire in the next 30 seconds
    // (or has already expired).
    if ($this->isAccessTokenExpired()) {
      if ($this->assertionCredentials) {
        $this->refreshTokenWithAssertion();
      } else {
        $this->client->getLogger()->debug('OAuth2 access token expired');
        if (! array_key_exists('refresh_token', $this->token)) {
          $error = "The OAuth 2.0 access token has expired,"
                  ." and a refresh token is not available. Refresh tokens"
                  ." are not returned for responses that were auto-approved.";

          $this->client->getLogger()->error($error);
          throw new Google_Auth_Exception($error);
        }
        $this->refreshToken($this->token['refresh_token']);
      }
    }

    $this->client->getLogger()->debug('OAuth2 authentication');

    // Add the OAuth2 header to the request
    $request->setRequestHeaders(
        array('Authorization' => 'Bearer ' . $this->token['access_token'])
    );

    return $request;
  }

  /**
   * Fetches a fresh access token with the given refresh token.
   * @param string $refreshToken
   * @return void
   */
  public function refreshToken($refreshToken)
  {
    $this->refreshTokenRequest(
        array(
          'client_id' => $this->client->getClassConfig($this, 'client_id'),
          'client_secret' => $this->client->getClassConfig($this, 'client_secret'),
          'refresh_token' => $refreshToken,
          'grant_type' => 'refresh_token'
        )
    );
  }

  /**
   * Fetches a fresh access token with a given assertion token.
   * @param Google_Auth_AssertionCredentials $assertionCredentials optional.
   * @return void
   */
  public function refreshTokenWithAssertion($assertionCredentials = null)
  {
    if (!$assertionCredentials) {
      $assertionCredentials = $this->assertionCredentials;
    }

    $cacheKey = $assertionCredentials->getCacheKey();

    if ($cacheKey) {
      // We can check whether we have a token available in the
      // cache. If it is expired, we can retrieve a new one from
      // the assertion.
      $token = $this->client->getCache()->get($cacheKey);
      if ($token) {
        $this->setAccessToken($token);
      }
      if (!$this->isAccessTokenExpired()) {
        return;
      }
    }

    $this->client->getLogger()->debug('OAuth2 access token expired');
    $this->refreshTokenRequest(
        array(
          'grant_type' => 'assertion',
          'assertion_type' => $assertionCredentials->assertionType,
          'assertion' => $assertionCredentials->generateAssertion(),
        )
    );

    if ($cacheKey) {
      // Attempt to cache the token.
      $this->client->getCache()->set(
          $cacheKey,
          $this->getAccessToken()
      );
    }
  }

  private function refreshTokenRequest($params)
  {
    if (isset($params['assertion'])) {
      $this->client->getLogger()->info(
          'OAuth2 access token refresh with Signed JWT assertion grants.'
      );
    } else {
      $this->client->getLogger()->info('OAuth2 access token refresh');
    }

    $http = new Google_Http_Request(
        self::OAUTH2_TOKEN_URI,
        'POST',
        array(),
        $params
    );
    $http->disableGzip();
    $request = $this->client->getIo()->makeRequest($http);

    $code = $request->getResponseHttpCode();
    $body = $request->getResponseBody();
    if (200 == $code) {
      $token = json_decode($body, true);
      if ($token == null) {
        throw new Google_Auth_Exception("Could not json decode the access token");
      }

      if (! isset($token['access_token']) || ! isset($token['expires_in'])) {
        throw new Google_Auth_Exception("Invalid token format");
      }

      if (isset($token['id_token'])) {
        $this->token['id_token'] = $token['id_token'];
      }
      $this->token['access_token'] = $token['access_token'];
      $this->token['expires_in'] = $token['expires_in'];
      $this->token['created'] = time();
    } else {
      throw new Google_Auth_Exception("Error refreshing the OAuth2 token, message: '$body'", $code);
    }
  }

  /**
   * Revoke an OAuth2 access token or refresh token. This method will revoke the current access
   * token, if a token isn't provided.
   * @throws Google_Auth_Exception
   * @param string|null $token The token (access token or a refresh token) that should be revoked.
   * @return boolean Returns True if the revocation was successful, otherwise False.
   */
  public function revokeToken($token = null)
  {
    if (!$token) {
      if (!$this->token) {
        // Not initialized, no token to actually revoke
        return false;
      } elseif (array_key_exists('refresh_token', $this->token)) {
        $token = $this->token['refresh_token'];
      } else {
        $token = $this->token['access_token'];
      }
    }
    $request = new Google_Http_Request(
        self::OAUTH2_REVOKE_URI,
        'POST',
        array(),
        "token=$token"
    );
    $request->disableGzip();
    $response = $this->client->getIo()->makeRequest($request);
    $code = $response->getResponseHttpCode();
    if ($code == 200) {
      $this->token = null;
      return true;
    }

    return false;
  }

  /**
   * Returns if the access_token is expired.
   * @return bool Returns True if the access_token is expired.
   */
  public function isAccessTokenExpired()
  {
    if (!$this->token || !isset($this->token['created'])) {
      return true;
    }

    // If the token is set to expire in the next 30 seconds.
    $expired = ($this->token['created']
        + ($this->token['expires_in'] - 30)) < time();

    return $expired;
  }

  // Gets federated sign-on certificates to use for verifying identity tokens.
  // Returns certs as array structure, where keys are key ids, and values
  // are PEM encoded certificates.
  private function getFederatedSignOnCerts()
  {
    return $this->retrieveCertsFromLocation(
        $this->client->getClassConfig($this, 'federated_signon_certs_url')
    );
  }

  /**
   * Retrieve and cache a certificates file.
   *
   * @param $url string location
   * @throws Google_Auth_Exception
   * @return array certificates
   */
  public function retrieveCertsFromLocation($url)
  {
    // If we're retrieving a local file, just grab it.
    if ("http" != substr($url, 0, 4)) {
      $file = file_get_contents($url);
      if ($file) {
        return json_decode($file, true);
      } else {
        throw new Google_Auth_Exception(
            "Failed to retrieve verification certificates: '" .
            $url . "'."
        );
      }
    }

    // This relies on makeRequest caching certificate responses.
    $request = $this->client->getIo()->makeRequest(
        new Google_Http_Request(
            $url
        )
    );
    if ($request->getResponseHttpCode() == 200) {
      $certs = json_decode($request->getResponseBody(), true);
      if ($certs) {
        return $certs;
      }
    }
    throw new Google_Auth_Exception(
        "Failed to retrieve verification certificates: '" .
        $request->getResponseBody() . "'.",
        $request->getResponseHttpCode()
    );
  }

  /**
   * Verifies an id token and returns the authenticated apiLoginTicket.
   * Throws an exception if the id token is not valid.
   * The audience parameter can be used to control which id tokens are
   * accepted.  By default, the id token must have been issued to this OAuth2 client.
   *
   * @param $id_token
   * @param $audience
   * @return Google_Auth_LoginTicket
   */
  public function verifyIdToken($id_token = null, $audience = null)
  {
    if (!$id_token) {
      $id_token = $this->token['id_token'];
    }
    $certs = $this->getFederatedSignonCerts();
    if (!$audience) {
      $audience = $this->client->getClassConfig($this, 'client_id');
    }

    return $this->verifySignedJwtWithCerts($id_token, $certs, $audience, self::OAUTH2_ISSUER);
  }

  /**
   * Verifies the id token, returns the verified token contents.
   *
   * @param $jwt string the token
   * @param $certs array of certificates
   * @param $required_audience string the expected consumer of the token
   * @param [$issuer] the expected issues, defaults to Google
   * @param [$max_expiry] the max lifetime of a token, defaults to MAX_TOKEN_LIFETIME_SECS
   * @throws Google_Auth_Exception
   * @return mixed token information if valid, false if not
   */
  public function verifySignedJwtWithCerts(
      $jwt,
      $certs,
      $required_audience,
      $issuer = null,
      $max_expiry = null
  ) {
    if (!$max_expiry) {
      // Set the maximum time we will accept a token for.
      $max_expiry = self::MAX_TOKEN_LIFETIME_SECS;
    }

    $segments = explode(".", $jwt);
    if (count($segments) != 3) {
      throw new Google_Auth_Exception("Wrong number of segments in token: $jwt");
    }
    $signed = $segments[0] . "." . $segments[1];
    $signature = Google_Utils::urlSafeB64Decode($segments[2]);

    // Parse envelope.
    $envelope = json_decode(Google_Utils::urlSafeB64Decode($segments[0]), true);
    if (!$envelope) {
      throw new Google_Auth_Exception("Can't parse token envelope: " . $segments[0]);
    }

    // Parse token
    $json_body = Google_Utils::urlSafeB64Decode($segments[1]);
    $payload = json_decode($json_body, true);
    if (!$payload) {
      throw new Google_Auth_Exception("Can't parse token payload: " . $segments[1]);
    }

    // Check signature
    $verified = false;
    foreach ($certs as $keyName => $pem) {
      $public_key = new Google_Verifier_Pem($pem);
      if ($public_key->verify($signed, $signature)) {
        $verified = true;
        break;
      }
    }

    if (!$verified) {
      throw new Google_Auth_Exception("Invalid token signature: $jwt");
    }

    // Check issued-at timestamp
    $iat = 0;
    if (array_key_exists("iat", $payload)) {
      $iat = $payload["iat"];
    }
    if (!$iat) {
      throw new Google_Auth_Exception("No issue time in token: $json_body");
    }
    $earliest = $iat - self::CLOCK_SKEW_SECS;

    // Check expiration timestamp
    $now = time();
    $exp = 0;
    if (array_key_exists("exp", $payload)) {
      $exp = $payload["exp"];
    }
    if (!$exp) {
      throw new Google_Auth_Exception("No expiration time in token: $json_body");
    }
    if ($exp >= $now + $max_expiry) {
      throw new Google_Auth_Exception(
          sprintf("Expiration time too far in future: %s", $json_body)
      );
    }

    $latest = $exp + self::CLOCK_SKEW_SECS;
    if ($now < $earliest) {
      throw new Google_Auth_Exception(
          sprintf(
              "Token used too early, %s < %s: %s",
              $now,
              $earliest,
              $json_body
          )
      );
    }
    if ($now > $latest) {
      throw new Google_Auth_Exception(
          sprintf(
              "Token used too late, %s > %s: %s",
              $now,
              $latest,
              $json_body
          )
      );
    }

    $iss = $payload['iss'];
    if ($issuer && $iss != $issuer) {
      throw new Google_Auth_Exception(
          sprintf(
              "Invalid issuer, %s != %s: %s",
              $iss,
              $issuer,
              $json_body
          )
      );
    }

    // Check audience
    $aud = $payload["aud"];
    if ($aud != $required_audience) {
      throw new Google_Auth_Exception(
          sprintf(
              "Wrong recipient, %s != %s:",
              $aud,
              $required_audience,
              $json_body
          )
      );
    }

    // All good.
    return new Google_Auth_LoginTicket($envelope, $payload);
  }

  /**
   * Add a parameter to the auth params if not empty string.
   */
  private function maybeAddParam($params, $name)
  {
    $param = $this->client->getClassConfig($this, $name);
    if ($param != '') {
      $params[$name] = $param;
    }
    return $params;
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Simple API access implementation. Can either be used to make requests
 * completely unauthenticated, or by using a Simple API Access developer
 * key.
 */
class Google_Auth_Simple extends Google_Auth_Abstract
{
  private $key = null;
  private $client;

  public function __construct(Google_Client $client, $config = null)
  {
    $this->client = $client;
  }

  /**
   * Perform an authenticated / signed apiHttpRequest.
   * This function takes the apiHttpRequest, calls apiAuth->sign on it
   * (which can modify the request in what ever way fits the auth mechanism)
   * and then calls apiCurlIO::makeRequest on the signed request
   *
   * @param Google_Http_Request $request
   * @return Google_Http_Request The resulting HTTP response including the
   * responseHttpCode, responseHeaders and responseBody.
   */
  public function authenticatedRequest(Google_Http_Request $request)
  {
    $request = $this->sign($request);
    return $this->io->makeRequest($request);
  }

  public function sign(Google_Http_Request $request)
  {
    $key = $this->client->getClassConfig($this, 'developer_key');
    if ($key) {
      $this->client->getLogger()->debug(
          'Simple API Access developer key authentication'
      );
      $request->setQueryParam('key', $key);
    }
    return $request;
  }
}
 
/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Abstract storage class
 *
 * @author Chris Chabot <chabotc@google.com>
 */
abstract class Google_Cache_Abstract
{
  
  abstract public function __construct(Google_Client $client);

  /**
   * Retrieves the data for the given key, or false if they
   * key is unknown or expired
   *
   * @param String $key The key who's data to retrieve
   * @param boolean|int $expiration Expiration time in seconds
   *
   */
  abstract public function get($key, $expiration = false);

  /**
   * Store the key => $value set. The $value is serialized
   * by this function so can be of any type
   *
   * @param string $key Key of the data
   * @param string $value data
   */
  abstract public function set($key, $value);

  /**
   * Removes the key/data pair for the given $key
   *
   * @param String $key
   */
  abstract public function delete($key);
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * A persistent storage class based on the APC cache, which is not
 * really very persistent, as soon as you restart your web server
 * the storage will be wiped, however for debugging and/or speed
 * it can be useful, and cache is a lot cheaper then storage.
 *
 * @author Chris Chabot <chabotc@google.com>
 */
class Google_Cache_Apc extends Google_Cache_Abstract
{
  /**
   * @var Google_Client the current client
   */
  private $client;

  public function __construct(Google_Client $client)
  {
    if (! function_exists('apc_add') ) {
      $error = "Apc functions not available";

      $client->getLogger()->error($error);
      throw new Google_Cache_Exception($error);
    }

    $this->client = $client;
  }

   /**
   * @inheritDoc
   */
  public function get($key, $expiration = false)
  {
    $ret = apc_fetch($key);
    if ($ret === false) {
      $this->client->getLogger()->debug(
          'APC cache miss',
          array('key' => $key)
      );
      return false;
    }
    if (is_numeric($expiration) && (time() - $ret['time'] > $expiration)) {
      $this->client->getLogger()->debug(
          'APC cache miss (expired)',
          array('key' => $key, 'var' => $ret)
      );
      $this->delete($key);
      return false;
    }

    $this->client->getLogger()->debug(
        'APC cache hit',
        array('key' => $key, 'var' => $ret)
    );

    return $ret['data'];
  }

  /**
   * @inheritDoc
   */
  public function set($key, $value)
  {
    $var = array('time' => time(), 'data' => $value);
    $rc = apc_store($key, $var);

    if ($rc == false) {
      $this->client->getLogger()->error(
          'APC cache set failed',
          array('key' => $key, 'var' => $var)
      );
      throw new Google_Cache_Exception("Couldn't store data");
    }

    $this->client->getLogger()->debug(
        'APC cache set',
        array('key' => $key, 'var' => $var)
    );
  }

  /**
   * @inheritDoc
   * @param String $key
   */
  public function delete($key)
  {
    $this->client->getLogger()->debug(
        'APC cache delete',
        array('key' => $key)
    );
    apc_delete($key);
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_Cache_Exception extends Google_Exception
{
}
 
/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/*
 * This class implements a basic on disk storage. While that does
 * work quite well it's not the most elegant and scalable solution.
 * It will also get you into a heap of trouble when you try to run
 * this in a clustered environment.
 *
 * @author Chris Chabot <chabotc@google.com>
 */
class Google_Cache_File extends Google_Cache_Abstract
{
  const MAX_LOCK_RETRIES = 10;
  private $path;
  private $fh;

  /**
   * @var Google_Client the current client
   */
  private $client;

  public function __construct(Google_Client $client)
  {
    $this->client = $client;
    $this->path = $this->client->getClassConfig($this, 'directory');
  }

  public function get($key, $expiration = false)
  {
    $storageFile = $this->getCacheFile($key);
    $data = false;

    if (!file_exists($storageFile)) {
      $this->client->getLogger()->debug(
          'File cache miss',
          array('key' => $key, 'file' => $storageFile)
      );
      return false;
    }

    if ($expiration) {
      $mtime = filemtime($storageFile);
      if ((time() - $mtime) >= $expiration) {
        $this->client->getLogger()->debug(
            'File cache miss (expired)',
            array('key' => $key, 'file' => $storageFile)
        );
        $this->delete($key);
        return false;
      }
    }

    if ($this->acquireReadLock($storageFile)) {
      if (filesize($storageFile) > 0) {
        $data = fread($this->fh, filesize($storageFile));
        $data =  unserialize($data);
      } else {
        $this->client->getLogger()->debug(
            'Cache file was empty',
            array('file' => $storageFile)
        );
      }
      $this->unlock($storageFile);
    }

    $this->client->getLogger()->debug(
        'File cache hit',
        array('key' => $key, 'file' => $storageFile, 'var' => $data)
    );

    return $data;
  }

  public function set($key, $value)
  {
    $storageFile = $this->getWriteableCacheFile($key);
    if ($this->acquireWriteLock($storageFile)) {
      // We serialize the whole request object, since we don't only want the
      // responseContent but also the postBody used, headers, size, etc.
      $data = serialize($value);
      $result = fwrite($this->fh, $data);
      $this->unlock($storageFile);

      $this->client->getLogger()->debug(
          'File cache set',
          array('key' => $key, 'file' => $storageFile, 'var' => $value)
      );
    } else {
      $this->client->getLogger()->notice(
          'File cache set failed',
          array('key' => $key, 'file' => $storageFile)
      );
    }
  }

  public function delete($key)
  {
    $file = $this->getCacheFile($key);
    if (file_exists($file) && !unlink($file)) {
      $this->client->getLogger()->error(
          'File cache delete failed',
          array('key' => $key, 'file' => $file)
      );
      throw new Google_Cache_Exception("Cache file could not be deleted");
    }

    $this->client->getLogger()->debug(
        'File cache delete',
        array('key' => $key, 'file' => $file)
    );
  }

  private function getWriteableCacheFile($file)
  {
    return $this->getCacheFile($file, true);
  }

  private function getCacheFile($file, $forWrite = false)
  {
    return $this->getCacheDir($file, $forWrite) . '/' . md5($file);
  }

  private function getCacheDir($file, $forWrite)
  {
    // use the first 2 characters of the hash as a directory prefix
    // this should prevent slowdowns due to huge directory listings
    // and thus give some basic amount of scalability
    $storageDir = $this->path . '/' . substr(md5($file), 0, 2);
    if ($forWrite && ! is_dir($storageDir)) {
      if (! mkdir($storageDir, 0755, true)) {
        $this->client->getLogger()->error(
            'File cache creation failed',
            array('dir' => $storageDir)
        );
        throw new Google_Cache_Exception("Could not create storage directory: $storageDir");
      }
    }
    return $storageDir;
  }

  private function acquireReadLock($storageFile)
  {
    return $this->acquireLock(LOCK_SH, $storageFile);
  }

  private function acquireWriteLock($storageFile)
  {
    $rc = $this->acquireLock(LOCK_EX, $storageFile);
    if (!$rc) {
      $this->client->getLogger()->notice(
          'File cache write lock failed',
          array('file' => $storageFile)
      );
      $this->delete($storageFile);
    }
    return $rc;
  }

  private function acquireLock($type, $storageFile)
  {
    $mode = $type == LOCK_EX ? "w" : "r";
    $this->fh = fopen($storageFile, $mode);
    if (!$this->fh) {
      $this->client->getLogger()->error(
          'Failed to open file during lock acquisition',
          array('file' => $storageFile)
      );
      return false;
    }
    $count = 0;
    while (!flock($this->fh, $type | LOCK_NB)) {
      // Sleep for 10ms.
      usleep(10000);
      if (++$count < self::MAX_LOCK_RETRIES) {
        return false;
      }
    }
    return true;
  }

  public function unlock($storageFile)
  {
    if ($this->fh) {
      flock($this->fh, LOCK_UN);
    }
  }
}
 
/*
 * Copyright 2008 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * A persistent storage class based on the memcache, which is not
 * really very persistent, as soon as you restart your memcache daemon
 * the storage will be wiped.
 *
 * Will use either the memcache or memcached extensions, preferring
 * memcached.
 *
 * @author Chris Chabot <chabotc@google.com>
 */
class Google_Cache_Memcache extends Google_Cache_Abstract
{
  private $connection = false;
  private $mc = false;
  private $host;
  private $port;

  /**
   * @var Google_Client the current client
   */
  private $client;

  public function __construct(Google_Client $client)
  {
    if (!function_exists('memcache_connect') && !class_exists("Memcached")) {
      $error = "Memcache functions not available";

      $client->getLogger()->error($error);
      throw new Google_Cache_Exception($error);
    }

    $this->client = $client;

    if ($client->isAppEngine()) {
      // No credentials needed for GAE.
      $this->mc = new Memcached();
      $this->connection = true;
    } else {
      $this->host = $client->getClassConfig($this, 'host');
      $this->port = $client->getClassConfig($this, 'port');
      if (empty($this->host) || (empty($this->port) && (string) $this->port != "0")) {
        $error = "You need to supply a valid memcache host and port";

        $client->getLogger()->error($error);
        throw new Google_Cache_Exception($error);
      }
    }
  }

  /**
   * @inheritDoc
   */
  public function get($key, $expiration = false)
  {
    $this->connect();
    $ret = false;
    if ($this->mc) {
      $ret = $this->mc->get($key);
    } else {
      $ret = memcache_get($this->connection, $key);
    }
    if ($ret === false) {
      $this->client->getLogger()->debug(
          'Memcache cache miss',
          array('key' => $key)
      );
      return false;
    }
    if (is_numeric($expiration) && (time() - $ret['time'] > $expiration)) {
      $this->client->getLogger()->debug(
          'Memcache cache miss (expired)',
          array('key' => $key, 'var' => $ret)
      );
      $this->delete($key);
      return false;
    }

    $this->client->getLogger()->debug(
        'Memcache cache hit',
        array('key' => $key, 'var' => $ret)
    );

    return $ret['data'];
  }

  /**
   * @inheritDoc
   * @param string $key
   * @param string $value
   * @throws Google_Cache_Exception
   */
  public function set($key, $value)
  {
    $this->connect();
    // we store it with the cache_time default expiration so objects will at
    // least get cleaned eventually.
    $data = array('time' => time(), 'data' => $value);
    $rc = false;
    if ($this->mc) {
      $rc = $this->mc->set($key, $data);
    } else {
      $rc = memcache_set($this->connection, $key, $data, false);
    }
    if ($rc == false) {
      $this->client->getLogger()->error(
          'Memcache cache set failed',
          array('key' => $key, 'var' => $data)
      );

      throw new Google_Cache_Exception("Couldn't store data in cache");
    }

    $this->client->getLogger()->debug(
        'Memcache cache set',
        array('key' => $key, 'var' => $data)
    );
  }

  /**
   * @inheritDoc
   * @param String $key
   */
  public function delete($key)
  {
    $this->connect();
    if ($this->mc) {
      $this->mc->delete($key, 0);
    } else {
      memcache_delete($this->connection, $key, 0);
    }

    $this->client->getLogger()->debug(
        'Memcache cache delete',
        array('key' => $key)
    );
  }

  /**
   * Lazy initialiser for memcache connection. Uses pconnect for to take
   * advantage of the persistence pool where possible.
   */
  private function connect()
  {
    if ($this->connection) {
      return;
    }

    if (class_exists("Memcached")) {
      $this->mc = new Memcached();
      $this->mc->addServer($this->host, $this->port);
       $this->connection = true;
    } else {
      $this->connection = memcache_pconnect($this->host, $this->port);
    }

    if (! $this->connection) {
      $error = "Couldn't connect to memcache server";

      $this->client->getLogger()->error($error);
      throw new Google_Cache_Exception($error);
    }
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * A blank storage class, for cases where caching is not
 * required.
 */
class Google_Cache_Null extends Google_Cache_Abstract
{
  public function __construct(Google_Client $client)
  {

  }

   /**
   * @inheritDoc
   */
  public function get($key, $expiration = false)
  {
    return false;
  }

  /**
   * @inheritDoc
   */
  public function set($key, $value)
  {
    // Nop.
  }

  /**
   * @inheritDoc
   * @param String $key
   */
  public function delete($key)
  {
    // Nop.
  }
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Signs data.
 *
 * @author Brian Eaton <beaton@google.com>
 */
abstract class Google_Signer_Abstract
{
  /**
   * Signs data, returns the signature as binary data.
   */
  abstract public function sign($data);
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Signs data.
 *
 * Only used for testing.
 *
 * @author Brian Eaton <beaton@google.com>
 */
class Google_Signer_P12 extends Google_Signer_Abstract
{
  // OpenSSL private key resource
  private $privateKey;

  // Creates a new signer from a .p12 file.
  public function __construct($p12, $password)
  {
    if (!function_exists('openssl_x509_read')) {
      throw new Google_Exception(
          'The Google PHP API library needs the openssl PHP extension'
      );
    }

    // If the private key is provided directly, then this isn't in the p12
    // format. Different versions of openssl support different p12 formats
    // and the key from google wasn't being accepted by the version available
    // at the time.
    if (!$password && strpos($p12, "-----BEGIN RSA PRIVATE KEY-----") !== false) {
      $this->privateKey = openssl_pkey_get_private($p12);
    } else {
      // This throws on error
      $certs = array();
      if (!openssl_pkcs12_read($p12, $certs, $password)) {
        throw new Google_Auth_Exception(
            "Unable to parse the p12 file.  " .
            "Is this a .p12 file?  Is the password correct?  OpenSSL error: " .
            openssl_error_string()
        );
      }
      // TODO(beaton): is this part of the contract for the openssl_pkcs12_read
      // method?  What happens if there are multiple private keys?  Do we care?
      if (!array_key_exists("pkey", $certs) || !$certs["pkey"]) {
        throw new Google_Auth_Exception("No private key found in p12 file.");
      }
      $this->privateKey = openssl_pkey_get_private($certs['pkey']);
    }

    if (!$this->privateKey) {
      throw new Google_Auth_Exception("Unable to load private key");
    }
  }

  public function __destruct()
  {
    if ($this->privateKey) {
      openssl_pkey_free($this->privateKey);
    }
  }

  public function sign($data)
  {
    if (version_compare(PHP_VERSION, '5.3.0') < 0) {
      throw new Google_Auth_Exception(
          "PHP 5.3.0 or higher is required to use service accounts."
      );
    }
    $hash = defined("OPENSSL_ALGO_SHA256") ? OPENSSL_ALGO_SHA256 : "sha256";
    if (!openssl_sign($data, $signature, $this->privateKey, $hash)) {
      throw new Google_Auth_Exception("Unable to sign data");
    }
    return $signature;
  }
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Verifies signatures.
 *
 * @author Brian Eaton <beaton@google.com>
 */
abstract class Google_Verifier_Abstract
{
  /**
   * Checks a signature, returns true if the signature is correct,
   * false otherwise.
   */
  abstract public function verify($data, $signature);
}
 
/*
 * Copyright 2011 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Verifies signatures using PEM encoded certificates.
 *
 * @author Brian Eaton <beaton@google.com>
 */
class Google_Verifier_Pem extends Google_Verifier_Abstract
{
  private $publicKey;

  /**
   * Constructs a verifier from the supplied PEM-encoded certificate.
   *
   * $pem: a PEM encoded certificate (not a file).
   * @param $pem
   * @throws Google_Auth_Exception
   * @throws Google_Exception
   */
  public function __construct($pem)
  {
    if (!function_exists('openssl_x509_read')) {
      throw new Google_Exception('Google API PHP client needs the openssl PHP extension');
    }
    $this->publicKey = openssl_x509_read($pem);
    if (!$this->publicKey) {
      throw new Google_Auth_Exception("Unable to parse PEM: $pem");
    }
  }

  public function __destruct()
  {
    if ($this->publicKey) {
      openssl_x509_free($this->publicKey);
    }
  }

  /**
   * Verifies the signature on data.
   *
   * Returns true if the signature is valid, false otherwise.
   * @param $data
   * @param $signature
   * @throws Google_Auth_Exception
   * @return bool
   */
  public function verify($data, $signature)
  {
    $hash = defined("OPENSSL_ALGO_SHA256") ? OPENSSL_ALGO_SHA256 : "sha256";
    $status = openssl_verify($data, $signature, $this->publicKey, $hash);
    if ($status === -1) {
      throw new Google_Auth_Exception('Signature verification error: ' . openssl_error_string());
    }
    return $status === 1;
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * Service definition for AdSense (v1.4).
 *
 * <p>
 * Gives AdSense publishers access to their inventory and the ability to
 * generate reports</p>
 *
 * <p>
 * For more information about this service, see the API
 * <a href="https://developers.google.com/adsense/management/" target="_blank">Documentation</a>
 * </p>
 *
 * @author Google, Inc.
 */
class Google_Service_AdSense extends Google_Service
{
  /** View and manage your AdSense data. */
  const ADSENSE =
      "https://www.googleapis.com/auth/adsense";
  /** View your AdSense data. */
  const ADSENSE_READONLY =
      "https://www.googleapis.com/auth/adsense.readonly";

  public $accounts;
  public $accounts_adclients;
  public $accounts_adunits;
  public $accounts_adunits_customchannels;
  public $accounts_alerts;
  public $accounts_customchannels;
  public $accounts_customchannels_adunits;
  public $accounts_payments;
  public $accounts_reports;
  public $accounts_reports_saved;
  public $accounts_savedadstyles;
  public $accounts_urlchannels;
  public $adclients;
  public $adunits;
  public $adunits_customchannels;
  public $alerts;
  public $customchannels;
  public $customchannels_adunits;
  public $metadata_dimensions;
  public $metadata_metrics;
  public $payments;
  public $reports;
  public $reports_saved;
  public $savedadstyles;
  public $urlchannels;
  

  /**
   * Constructs the internal representation of the AdSense service.
   *
   * @param Google_Client $client
   */
  public function __construct(Google_Client $client)
  {
    parent::__construct($client);
    $this->servicePath = 'adsense/v1.4/';
    $this->version = 'v1.4';
    $this->serviceName = 'adsense';

    $this->accounts = new Google_Service_AdSense_Accounts_Resource(
        $this,
        $this->serviceName,
        'accounts',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'accounts/{accountId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'tree' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
              ),
            ),'list' => array(
              'path' => 'accounts',
              'httpMethod' => 'GET',
              'parameters' => array(
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_adclients = new Google_Service_AdSense_AccountsAdclients_Resource(
        $this,
        $this->serviceName,
        'adclients',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'accounts/{accountId}/adclients',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_adunits = new Google_Service_AdSense_AccountsAdunits_Resource(
        $this,
        $this->serviceName,
        'adunits',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/adunits/{adUnitId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adUnitId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'getAdCode' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/adunits/{adUnitId}/adcode',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adUnitId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/adunits',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'includeInactive' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_adunits_customchannels = new Google_Service_AdSense_AccountsAdunitsCustomchannels_Resource(
        $this,
        $this->serviceName,
        'customchannels',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/adunits/{adUnitId}/customchannels',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adUnitId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_alerts = new Google_Service_AdSense_AccountsAlerts_Resource(
        $this,
        $this->serviceName,
        'alerts',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'accounts/{accountId}/alerts/{alertId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'alertId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'accounts/{accountId}/alerts',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'locale' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_customchannels = new Google_Service_AdSense_AccountsCustomchannels_Resource(
        $this,
        $this->serviceName,
        'customchannels',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/customchannels/{customChannelId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customChannelId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/customchannels',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_customchannels_adunits = new Google_Service_AdSense_AccountsCustomchannelsAdunits_Resource(
        $this,
        $this->serviceName,
        'adunits',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/customchannels/{customChannelId}/adunits',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customChannelId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'includeInactive' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_payments = new Google_Service_AdSense_AccountsPayments_Resource(
        $this,
        $this->serviceName,
        'payments',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'accounts/{accountId}/payments',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_reports = new Google_Service_AdSense_AccountsReports_Resource(
        $this,
        $this->serviceName,
        'reports',
        array(
          'methods' => array(
            'generate' => array(
              'path' => 'accounts/{accountId}/reports',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'startDate' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'endDate' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'sort' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'locale' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'metric' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'filter' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'currency' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'startIndex' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'useTimezoneReporting' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
                'dimension' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_reports_saved = new Google_Service_AdSense_AccountsReportsSaved_Resource(
        $this,
        $this->serviceName,
        'saved',
        array(
          'methods' => array(
            'generate' => array(
              'path' => 'accounts/{accountId}/reports/{savedReportId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'savedReportId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'locale' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'startIndex' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'list' => array(
              'path' => 'accounts/{accountId}/reports/saved',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_savedadstyles = new Google_Service_AdSense_AccountsSavedadstyles_Resource(
        $this,
        $this->serviceName,
        'savedadstyles',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'accounts/{accountId}/savedadstyles/{savedAdStyleId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'savedAdStyleId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'accounts/{accountId}/savedadstyles',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->accounts_urlchannels = new Google_Service_AdSense_AccountsUrlchannels_Resource(
        $this,
        $this->serviceName,
        'urlchannels',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'accounts/{accountId}/adclients/{adClientId}/urlchannels',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->adclients = new Google_Service_AdSense_Adclients_Resource(
        $this,
        $this->serviceName,
        'adclients',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'adclients',
              'httpMethod' => 'GET',
              'parameters' => array(
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->adunits = new Google_Service_AdSense_Adunits_Resource(
        $this,
        $this->serviceName,
        'adunits',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'adclients/{adClientId}/adunits/{adUnitId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adUnitId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'getAdCode' => array(
              'path' => 'adclients/{adClientId}/adunits/{adUnitId}/adcode',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adUnitId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'adclients/{adClientId}/adunits',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'includeInactive' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->adunits_customchannels = new Google_Service_AdSense_AdunitsCustomchannels_Resource(
        $this,
        $this->serviceName,
        'customchannels',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'adclients/{adClientId}/adunits/{adUnitId}/customchannels',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'adUnitId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->alerts = new Google_Service_AdSense_Alerts_Resource(
        $this,
        $this->serviceName,
        'alerts',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'alerts/{alertId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'alertId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'alerts',
              'httpMethod' => 'GET',
              'parameters' => array(
                'locale' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
    $this->customchannels = new Google_Service_AdSense_Customchannels_Resource(
        $this,
        $this->serviceName,
        'customchannels',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'adclients/{adClientId}/customchannels/{customChannelId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customChannelId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'adclients/{adClientId}/customchannels',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->customchannels_adunits = new Google_Service_AdSense_CustomchannelsAdunits_Resource(
        $this,
        $this->serviceName,
        'adunits',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'adclients/{adClientId}/customchannels/{customChannelId}/adunits',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customChannelId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'includeInactive' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->metadata_dimensions = new Google_Service_AdSense_MetadataDimensions_Resource(
        $this,
        $this->serviceName,
        'dimensions',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'metadata/dimensions',
              'httpMethod' => 'GET',
              'parameters' => array(),
            ),
          )
        )
    );
    $this->metadata_metrics = new Google_Service_AdSense_MetadataMetrics_Resource(
        $this,
        $this->serviceName,
        'metrics',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'metadata/metrics',
              'httpMethod' => 'GET',
              'parameters' => array(),
            ),
          )
        )
    );
    $this->payments = new Google_Service_AdSense_Payments_Resource(
        $this,
        $this->serviceName,
        'payments',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'payments',
              'httpMethod' => 'GET',
              'parameters' => array(),
            ),
          )
        )
    );
    $this->reports = new Google_Service_AdSense_Reports_Resource(
        $this,
        $this->serviceName,
        'reports',
        array(
          'methods' => array(
            'generate' => array(
              'path' => 'reports',
              'httpMethod' => 'GET',
              'parameters' => array(
                'startDate' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'endDate' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'sort' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'locale' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'metric' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'filter' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'currency' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'startIndex' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'useTimezoneReporting' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
                'dimension' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
                'accountId' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'repeated' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->reports_saved = new Google_Service_AdSense_ReportsSaved_Resource(
        $this,
        $this->serviceName,
        'saved',
        array(
          'methods' => array(
            'generate' => array(
              'path' => 'reports/{savedReportId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'savedReportId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'locale' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'startIndex' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'list' => array(
              'path' => 'reports/saved',
              'httpMethod' => 'GET',
              'parameters' => array(
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->savedadstyles = new Google_Service_AdSense_Savedadstyles_Resource(
        $this,
        $this->serviceName,
        'savedadstyles',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'savedadstyles/{savedAdStyleId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'savedAdStyleId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'savedadstyles',
              'httpMethod' => 'GET',
              'parameters' => array(
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->urlchannels = new Google_Service_AdSense_Urlchannels_Resource(
        $this,
        $this->serviceName,
        'urlchannels',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'adclients/{adClientId}/urlchannels',
              'httpMethod' => 'GET',
              'parameters' => array(
                'adClientId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'pageToken' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'maxResults' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
  }
}


/**
 * The "accounts" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $accounts = $adsenseService->accounts;
 *  </code>
 */
class Google_Service_AdSense_Accounts_Resource extends Google_Service_Resource
{

  /**
   * Get information about the selected AdSense account. (accounts.get)
   *
   * @param string $accountId Account to get information about.
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool tree Whether the tree of sub accounts should be returned.
   * @return Google_Service_AdSense_Account
   */
  public function get($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_Account");
  }

  /**
   * List all accounts available to this AdSense account. (accounts.listAccounts)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through
   * accounts. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of accounts to include in the
   * response, used for paging.
   * @return Google_Service_AdSense_Accounts
   */
  public function listAccounts($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Accounts");
  }
}

/**
 * The "adclients" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $adclients = $adsenseService->adclients;
 *  </code>
 */
class Google_Service_AdSense_AccountsAdclients_Resource extends Google_Service_Resource
{

  /**
   * List all ad clients in the specified account.
   * (adclients.listAccountsAdclients)
   *
   * @param string $accountId Account for which to list ad clients.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through ad
   * clients. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of ad clients to include in the
   * response, used for paging.
   * @return Google_Service_AdSense_AdClients
   */
  public function listAccountsAdclients($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_AdClients");
  }
}
/**
 * The "adunits" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $adunits = $adsenseService->adunits;
 *  </code>
 */
class Google_Service_AdSense_AccountsAdunits_Resource extends Google_Service_Resource
{

  /**
   * Gets the specified ad unit in the specified ad client for the specified
   * account. (adunits.get)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client for which to get the ad unit.
   * @param string $adUnitId Ad unit to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_AdUnit
   */
  public function get($accountId, $adClientId, $adUnitId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId, 'adUnitId' => $adUnitId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_AdUnit");
  }

  /**
   * Get ad code for the specified ad unit. (adunits.getAdCode)
   *
   * @param string $accountId Account which contains the ad client.
   * @param string $adClientId Ad client with contains the ad unit.
   * @param string $adUnitId Ad unit to get the code for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_AdCode
   */
  public function getAdCode($accountId, $adClientId, $adUnitId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId, 'adUnitId' => $adUnitId);
    $params = array_merge($params, $optParams);
    return $this->call('getAdCode', array($params), "Google_Service_AdSense_AdCode");
  }

  /**
   * List all ad units in the specified ad client for the specified account.
   * (adunits.listAccountsAdunits)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client for which to list ad units.
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool includeInactive Whether to include inactive ad units.
   * Default: true.
   * @opt_param string pageToken A continuation token, used to page through ad
   * units. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of ad units to include in the
   * response, used for paging.
   * @return Google_Service_AdSense_AdUnits
   */
  public function listAccountsAdunits($accountId, $adClientId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_AdUnits");
  }
}

/**
 * The "customchannels" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $customchannels = $adsenseService->customchannels;
 *  </code>
 */
class Google_Service_AdSense_AccountsAdunitsCustomchannels_Resource extends Google_Service_Resource
{

  /**
   * List all custom channels which the specified ad unit belongs to.
   * (customchannels.listAccountsAdunitsCustomchannels)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client which contains the ad unit.
   * @param string $adUnitId Ad unit for which to list custom channels.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through custom
   * channels. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of custom channels to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_CustomChannels
   */
  public function listAccountsAdunitsCustomchannels($accountId, $adClientId, $adUnitId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId, 'adUnitId' => $adUnitId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_CustomChannels");
  }
}
/**
 * The "alerts" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $alerts = $adsenseService->alerts;
 *  </code>
 */
class Google_Service_AdSense_AccountsAlerts_Resource extends Google_Service_Resource
{

  /**
   * Dismiss (delete) the specified alert from the specified publisher AdSense
   * account. (alerts.delete)
   *
   * @param string $accountId Account which contains the ad unit.
   * @param string $alertId Alert to delete.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $alertId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'alertId' => $alertId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * List the alerts for the specified AdSense account.
   * (alerts.listAccountsAlerts)
   *
   * @param string $accountId Account for which to retrieve the alerts.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string locale The locale to use for translating alert messages.
   * The account locale will be used if this is not supplied. The AdSense default
   * (English) will be used if the supplied locale is invalid or unsupported.
   * @return Google_Service_AdSense_Alerts
   */
  public function listAccountsAlerts($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Alerts");
  }
}
/**
 * The "customchannels" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $customchannels = $adsenseService->customchannels;
 *  </code>
 */
class Google_Service_AdSense_AccountsCustomchannels_Resource extends Google_Service_Resource
{

  /**
   * Get the specified custom channel from the specified ad client for the
   * specified account. (customchannels.get)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client which contains the custom channel.
   * @param string $customChannelId Custom channel to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_CustomChannel
   */
  public function get($accountId, $adClientId, $customChannelId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId, 'customChannelId' => $customChannelId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_CustomChannel");
  }

  /**
   * List all custom channels in the specified ad client for the specified
   * account. (customchannels.listAccountsCustomchannels)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client for which to list custom channels.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through custom
   * channels. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of custom channels to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_CustomChannels
   */
  public function listAccountsCustomchannels($accountId, $adClientId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_CustomChannels");
  }
}

/**
 * The "adunits" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $adunits = $adsenseService->adunits;
 *  </code>
 */
class Google_Service_AdSense_AccountsCustomchannelsAdunits_Resource extends Google_Service_Resource
{

  /**
   * List all ad units in the specified custom channel.
   * (adunits.listAccountsCustomchannelsAdunits)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client which contains the custom channel.
   * @param string $customChannelId Custom channel for which to list ad units.
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool includeInactive Whether to include inactive ad units.
   * Default: true.
   * @opt_param int maxResults The maximum number of ad units to include in the
   * response, used for paging.
   * @opt_param string pageToken A continuation token, used to page through ad
   * units. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @return Google_Service_AdSense_AdUnits
   */
  public function listAccountsCustomchannelsAdunits($accountId, $adClientId, $customChannelId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId, 'customChannelId' => $customChannelId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_AdUnits");
  }
}
/**
 * The "payments" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $payments = $adsenseService->payments;
 *  </code>
 */
class Google_Service_AdSense_AccountsPayments_Resource extends Google_Service_Resource
{

  /**
   * List the payments for the specified AdSense account.
   * (payments.listAccountsPayments)
   *
   * @param string $accountId Account for which to retrieve the payments.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_Payments
   */
  public function listAccountsPayments($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Payments");
  }
}
/**
 * The "reports" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $reports = $adsenseService->reports;
 *  </code>
 */
class Google_Service_AdSense_AccountsReports_Resource extends Google_Service_Resource
{

  /**
   * Generate an AdSense report based on the report request sent in the query
   * parameters. Returns the result as JSON; to retrieve output in CSV format
   * specify "alt=csv" as a query parameter. (reports.generate)
   *
   * @param string $accountId Account upon which to report.
   * @param string $startDate Start of the date range to report on in "YYYY-MM-DD"
   * format, inclusive.
   * @param string $endDate End of the date range to report on in "YYYY-MM-DD"
   * format, inclusive.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string sort The name of a dimension or metric to sort the
   * resulting report on, optionally prefixed with "+" to sort ascending or "-" to
   * sort descending. If no prefix is specified, the column is sorted ascending.
   * @opt_param string locale Optional locale to use for translating report output
   * to a local language. Defaults to "en_US" if not specified.
   * @opt_param string metric Numeric columns to include in the report.
   * @opt_param int maxResults The maximum number of rows of report data to
   * return.
   * @opt_param string filter Filters to be run on the report.
   * @opt_param string currency Optional currency to use when reporting on
   * monetary metrics. Defaults to the account's currency if not set.
   * @opt_param int startIndex Index of the first row of report data to return.
   * @opt_param bool useTimezoneReporting Whether the report should be generated
   * in the AdSense account's local timezone. If false default PST/PDT timezone
   * will be used.
   * @opt_param string dimension Dimensions to base the report on.
   * @return Google_Service_AdSense_AdsenseReportsGenerateResponse
   */
  public function generate($accountId, $startDate, $endDate, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'startDate' => $startDate, 'endDate' => $endDate);
    $params = array_merge($params, $optParams);
    return $this->call('generate', array($params), "Google_Service_AdSense_AdsenseReportsGenerateResponse");
  }
}

/**
 * The "saved" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $saved = $adsenseService->saved;
 *  </code>
 */
class Google_Service_AdSense_AccountsReportsSaved_Resource extends Google_Service_Resource
{

  /**
   * Generate an AdSense report based on the saved report ID sent in the query
   * parameters. (saved.generate)
   *
   * @param string $accountId Account to which the saved reports belong.
   * @param string $savedReportId The saved report to retrieve.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string locale Optional locale to use for translating report output
   * to a local language. Defaults to "en_US" if not specified.
   * @opt_param int startIndex Index of the first row of report data to return.
   * @opt_param int maxResults The maximum number of rows of report data to
   * return.
   * @return Google_Service_AdSense_AdsenseReportsGenerateResponse
   */
  public function generate($accountId, $savedReportId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'savedReportId' => $savedReportId);
    $params = array_merge($params, $optParams);
    return $this->call('generate', array($params), "Google_Service_AdSense_AdsenseReportsGenerateResponse");
  }

  /**
   * List all saved reports in the specified AdSense account.
   * (saved.listAccountsReportsSaved)
   *
   * @param string $accountId Account to which the saved reports belong.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through saved
   * reports. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of saved reports to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_SavedReports
   */
  public function listAccountsReportsSaved($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_SavedReports");
  }
}
/**
 * The "savedadstyles" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $savedadstyles = $adsenseService->savedadstyles;
 *  </code>
 */
class Google_Service_AdSense_AccountsSavedadstyles_Resource extends Google_Service_Resource
{

  /**
   * List a specific saved ad style for the specified account. (savedadstyles.get)
   *
   * @param string $accountId Account for which to get the saved ad style.
   * @param string $savedAdStyleId Saved ad style to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_SavedAdStyle
   */
  public function get($accountId, $savedAdStyleId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'savedAdStyleId' => $savedAdStyleId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_SavedAdStyle");
  }

  /**
   * List all saved ad styles in the specified account.
   * (savedadstyles.listAccountsSavedadstyles)
   *
   * @param string $accountId Account for which to list saved ad styles.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through saved
   * ad styles. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of saved ad styles to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_SavedAdStyles
   */
  public function listAccountsSavedadstyles($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_SavedAdStyles");
  }
}
/**
 * The "urlchannels" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $urlchannels = $adsenseService->urlchannels;
 *  </code>
 */
class Google_Service_AdSense_AccountsUrlchannels_Resource extends Google_Service_Resource
{

  /**
   * List all URL channels in the specified ad client for the specified account.
   * (urlchannels.listAccountsUrlchannels)
   *
   * @param string $accountId Account to which the ad client belongs.
   * @param string $adClientId Ad client for which to list URL channels.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through URL
   * channels. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of URL channels to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_UrlChannels
   */
  public function listAccountsUrlchannels($accountId, $adClientId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'adClientId' => $adClientId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_UrlChannels");
  }
}

/**
 * The "adclients" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $adclients = $adsenseService->adclients;
 *  </code>
 */
class Google_Service_AdSense_Adclients_Resource extends Google_Service_Resource
{

  /**
   * List all ad clients in this AdSense account. (adclients.listAdclients)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through ad
   * clients. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of ad clients to include in the
   * response, used for paging.
   * @return Google_Service_AdSense_AdClients
   */
  public function listAdclients($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_AdClients");
  }
}

/**
 * The "adunits" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $adunits = $adsenseService->adunits;
 *  </code>
 */
class Google_Service_AdSense_Adunits_Resource extends Google_Service_Resource
{

  /**
   * Gets the specified ad unit in the specified ad client. (adunits.get)
   *
   * @param string $adClientId Ad client for which to get the ad unit.
   * @param string $adUnitId Ad unit to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_AdUnit
   */
  public function get($adClientId, $adUnitId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId, 'adUnitId' => $adUnitId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_AdUnit");
  }

  /**
   * Get ad code for the specified ad unit. (adunits.getAdCode)
   *
   * @param string $adClientId Ad client with contains the ad unit.
   * @param string $adUnitId Ad unit to get the code for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_AdCode
   */
  public function getAdCode($adClientId, $adUnitId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId, 'adUnitId' => $adUnitId);
    $params = array_merge($params, $optParams);
    return $this->call('getAdCode', array($params), "Google_Service_AdSense_AdCode");
  }

  /**
   * List all ad units in the specified ad client for this AdSense account.
   * (adunits.listAdunits)
   *
   * @param string $adClientId Ad client for which to list ad units.
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool includeInactive Whether to include inactive ad units.
   * Default: true.
   * @opt_param string pageToken A continuation token, used to page through ad
   * units. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of ad units to include in the
   * response, used for paging.
   * @return Google_Service_AdSense_AdUnits
   */
  public function listAdunits($adClientId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_AdUnits");
  }
}

/**
 * The "customchannels" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $customchannels = $adsenseService->customchannels;
 *  </code>
 */
class Google_Service_AdSense_AdunitsCustomchannels_Resource extends Google_Service_Resource
{

  /**
   * List all custom channels which the specified ad unit belongs to.
   * (customchannels.listAdunitsCustomchannels)
   *
   * @param string $adClientId Ad client which contains the ad unit.
   * @param string $adUnitId Ad unit for which to list custom channels.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through custom
   * channels. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of custom channels to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_CustomChannels
   */
  public function listAdunitsCustomchannels($adClientId, $adUnitId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId, 'adUnitId' => $adUnitId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_CustomChannels");
  }
}

/**
 * The "alerts" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $alerts = $adsenseService->alerts;
 *  </code>
 */
class Google_Service_AdSense_Alerts_Resource extends Google_Service_Resource
{

  /**
   * Dismiss (delete) the specified alert from the publisher's AdSense account.
   * (alerts.delete)
   *
   * @param string $alertId Alert to delete.
   * @param array $optParams Optional parameters.
   */
  public function delete($alertId, $optParams = array())
  {
    $params = array('alertId' => $alertId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * List the alerts for this AdSense account. (alerts.listAlerts)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param string locale The locale to use for translating alert messages.
   * The account locale will be used if this is not supplied. The AdSense default
   * (English) will be used if the supplied locale is invalid or unsupported.
   * @return Google_Service_AdSense_Alerts
   */
  public function listAlerts($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Alerts");
  }
}

/**
 * The "customchannels" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $customchannels = $adsenseService->customchannels;
 *  </code>
 */
class Google_Service_AdSense_Customchannels_Resource extends Google_Service_Resource
{

  /**
   * Get the specified custom channel from the specified ad client.
   * (customchannels.get)
   *
   * @param string $adClientId Ad client which contains the custom channel.
   * @param string $customChannelId Custom channel to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_CustomChannel
   */
  public function get($adClientId, $customChannelId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId, 'customChannelId' => $customChannelId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_CustomChannel");
  }

  /**
   * List all custom channels in the specified ad client for this AdSense account.
   * (customchannels.listCustomchannels)
   *
   * @param string $adClientId Ad client for which to list custom channels.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through custom
   * channels. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of custom channels to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_CustomChannels
   */
  public function listCustomchannels($adClientId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_CustomChannels");
  }
}

/**
 * The "adunits" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $adunits = $adsenseService->adunits;
 *  </code>
 */
class Google_Service_AdSense_CustomchannelsAdunits_Resource extends Google_Service_Resource
{

  /**
   * List all ad units in the specified custom channel.
   * (adunits.listCustomchannelsAdunits)
   *
   * @param string $adClientId Ad client which contains the custom channel.
   * @param string $customChannelId Custom channel for which to list ad units.
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool includeInactive Whether to include inactive ad units.
   * Default: true.
   * @opt_param string pageToken A continuation token, used to page through ad
   * units. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of ad units to include in the
   * response, used for paging.
   * @return Google_Service_AdSense_AdUnits
   */
  public function listCustomchannelsAdunits($adClientId, $customChannelId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId, 'customChannelId' => $customChannelId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_AdUnits");
  }
}

/**
 * The "metadata" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $metadata = $adsenseService->metadata;
 *  </code>
 */
class Google_Service_AdSense_Metadata_Resource extends Google_Service_Resource
{
}

/**
 * The "dimensions" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $dimensions = $adsenseService->dimensions;
 *  </code>
 */
class Google_Service_AdSense_MetadataDimensions_Resource extends Google_Service_Resource
{

  /**
   * List the metadata for the dimensions available to this AdSense account.
   * (dimensions.listMetadataDimensions)
   *
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_Metadata
   */
  public function listMetadataDimensions($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Metadata");
  }
}
/**
 * The "metrics" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $metrics = $adsenseService->metrics;
 *  </code>
 */
class Google_Service_AdSense_MetadataMetrics_Resource extends Google_Service_Resource
{

  /**
   * List the metadata for the metrics available to this AdSense account.
   * (metrics.listMetadataMetrics)
   *
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_Metadata
   */
  public function listMetadataMetrics($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Metadata");
  }
}

/**
 * The "payments" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $payments = $adsenseService->payments;
 *  </code>
 */
class Google_Service_AdSense_Payments_Resource extends Google_Service_Resource
{

  /**
   * List the payments for this AdSense account. (payments.listPayments)
   *
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_Payments
   */
  public function listPayments($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_Payments");
  }
}

/**
 * The "reports" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $reports = $adsenseService->reports;
 *  </code>
 */
class Google_Service_AdSense_Reports_Resource extends Google_Service_Resource
{

  /**
   * Generate an AdSense report based on the report request sent in the query
   * parameters. Returns the result as JSON; to retrieve output in CSV format
   * specify "alt=csv" as a query parameter. (reports.generate)
   *
   * @param string $startDate Start of the date range to report on in "YYYY-MM-DD"
   * format, inclusive.
   * @param string $endDate End of the date range to report on in "YYYY-MM-DD"
   * format, inclusive.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string sort The name of a dimension or metric to sort the
   * resulting report on, optionally prefixed with "+" to sort ascending or "-" to
   * sort descending. If no prefix is specified, the column is sorted ascending.
   * @opt_param string locale Optional locale to use for translating report output
   * to a local language. Defaults to "en_US" if not specified.
   * @opt_param string metric Numeric columns to include in the report.
   * @opt_param int maxResults The maximum number of rows of report data to
   * return.
   * @opt_param string filter Filters to be run on the report.
   * @opt_param string currency Optional currency to use when reporting on
   * monetary metrics. Defaults to the account's currency if not set.
   * @opt_param int startIndex Index of the first row of report data to return.
   * @opt_param bool useTimezoneReporting Whether the report should be generated
   * in the AdSense account's local timezone. If false default PST/PDT timezone
   * will be used.
   * @opt_param string dimension Dimensions to base the report on.
   * @opt_param string accountId Accounts upon which to report.
   * @return Google_Service_AdSense_AdsenseReportsGenerateResponse
   */
  public function generate($startDate, $endDate, $optParams = array())
  {
    $params = array('startDate' => $startDate, 'endDate' => $endDate);
    $params = array_merge($params, $optParams);
    return $this->call('generate', array($params), "Google_Service_AdSense_AdsenseReportsGenerateResponse");
  }
}

/**
 * The "saved" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $saved = $adsenseService->saved;
 *  </code>
 */
class Google_Service_AdSense_ReportsSaved_Resource extends Google_Service_Resource
{

  /**
   * Generate an AdSense report based on the saved report ID sent in the query
   * parameters. (saved.generate)
   *
   * @param string $savedReportId The saved report to retrieve.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string locale Optional locale to use for translating report output
   * to a local language. Defaults to "en_US" if not specified.
   * @opt_param int startIndex Index of the first row of report data to return.
   * @opt_param int maxResults The maximum number of rows of report data to
   * return.
   * @return Google_Service_AdSense_AdsenseReportsGenerateResponse
   */
  public function generate($savedReportId, $optParams = array())
  {
    $params = array('savedReportId' => $savedReportId);
    $params = array_merge($params, $optParams);
    return $this->call('generate', array($params), "Google_Service_AdSense_AdsenseReportsGenerateResponse");
  }

  /**
   * List all saved reports in this AdSense account. (saved.listReportsSaved)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through saved
   * reports. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of saved reports to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_SavedReports
   */
  public function listReportsSaved($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_SavedReports");
  }
}

/**
 * The "savedadstyles" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $savedadstyles = $adsenseService->savedadstyles;
 *  </code>
 */
class Google_Service_AdSense_Savedadstyles_Resource extends Google_Service_Resource
{

  /**
   * Get a specific saved ad style from the user's account. (savedadstyles.get)
   *
   * @param string $savedAdStyleId Saved ad style to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_AdSense_SavedAdStyle
   */
  public function get($savedAdStyleId, $optParams = array())
  {
    $params = array('savedAdStyleId' => $savedAdStyleId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_AdSense_SavedAdStyle");
  }

  /**
   * List all saved ad styles in the user's account.
   * (savedadstyles.listSavedadstyles)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through saved
   * ad styles. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of saved ad styles to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_SavedAdStyles
   */
  public function listSavedadstyles($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_SavedAdStyles");
  }
}

/**
 * The "urlchannels" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adsenseService = new Google_Service_AdSense(...);
 *   $urlchannels = $adsenseService->urlchannels;
 *  </code>
 */
class Google_Service_AdSense_Urlchannels_Resource extends Google_Service_Resource
{

  /**
   * List all URL channels in the specified ad client for this AdSense account.
   * (urlchannels.listUrlchannels)
   *
   * @param string $adClientId Ad client for which to list URL channels.
   * @param array $optParams Optional parameters.
   *
   * @opt_param string pageToken A continuation token, used to page through URL
   * channels. To retrieve the next page, set this parameter to the value of
   * "nextPageToken" from the previous response.
   * @opt_param int maxResults The maximum number of URL channels to include in
   * the response, used for paging.
   * @return Google_Service_AdSense_UrlChannels
   */
  public function listUrlchannels($adClientId, $optParams = array())
  {
    $params = array('adClientId' => $adClientId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_AdSense_UrlChannels");
  }
}




class Google_Service_AdSense_Account extends Google_Collection
{
  protected $collection_key = 'subAccounts';
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $kind;
  public $name;
  public $premium;
  protected $subAccountsType = 'Google_Service_AdSense_Account';
  protected $subAccountsDataType = 'array';
  public $timezone;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setPremium($premium)
  {
    $this->premium = $premium;
  }
  public function getPremium()
  {
    return $this->premium;
  }
  public function setSubAccounts($subAccounts)
  {
    $this->subAccounts = $subAccounts;
  }
  public function getSubAccounts()
  {
    return $this->subAccounts;
  }
  public function setTimezone($timezone)
  {
    $this->timezone = $timezone;
  }
  public function getTimezone()
  {
    return $this->timezone;
  }
}

class Google_Service_AdSense_Accounts extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_Account';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}

class Google_Service_AdSense_AdClient extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $arcOptIn;
  public $arcReviewMode;
  public $id;
  public $kind;
  public $productCode;
  public $supportsReporting;


  public function setArcOptIn($arcOptIn)
  {
    $this->arcOptIn = $arcOptIn;
  }
  public function getArcOptIn()
  {
    return $this->arcOptIn;
  }
  public function setArcReviewMode($arcReviewMode)
  {
    $this->arcReviewMode = $arcReviewMode;
  }
  public function getArcReviewMode()
  {
    return $this->arcReviewMode;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setProductCode($productCode)
  {
    $this->productCode = $productCode;
  }
  public function getProductCode()
  {
    return $this->productCode;
  }
  public function setSupportsReporting($supportsReporting)
  {
    $this->supportsReporting = $supportsReporting;
  }
  public function getSupportsReporting()
  {
    return $this->supportsReporting;
  }
}

class Google_Service_AdSense_AdClients extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_AdClient';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}

class Google_Service_AdSense_AdCode extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $adCode;
  public $kind;


  public function setAdCode($adCode)
  {
    $this->adCode = $adCode;
  }
  public function getAdCode()
  {
    return $this->adCode;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_AdSense_AdStyle extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $colorsType = 'Google_Service_AdSense_AdStyleColors';
  protected $colorsDataType = '';
  public $corners;
  protected $fontType = 'Google_Service_AdSense_AdStyleFont';
  protected $fontDataType = '';
  public $kind;


  public function setColors(Google_Service_AdSense_AdStyleColors $colors)
  {
    $this->colors = $colors;
  }
  public function getColors()
  {
    return $this->colors;
  }
  public function setCorners($corners)
  {
    $this->corners = $corners;
  }
  public function getCorners()
  {
    return $this->corners;
  }
  public function setFont(Google_Service_AdSense_AdStyleFont $font)
  {
    $this->font = $font;
  }
  public function getFont()
  {
    return $this->font;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_AdSense_AdStyleColors extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $background;
  public $border;
  public $text;
  public $title;
  public $url;


  public function setBackground($background)
  {
    $this->background = $background;
  }
  public function getBackground()
  {
    return $this->background;
  }
  public function setBorder($border)
  {
    $this->border = $border;
  }
  public function getBorder()
  {
    return $this->border;
  }
  public function setText($text)
  {
    $this->text = $text;
  }
  public function getText()
  {
    return $this->text;
  }
  public function setTitle($title)
  {
    $this->title = $title;
  }
  public function getTitle()
  {
    return $this->title;
  }
  public function setUrl($url)
  {
    $this->url = $url;
  }
  public function getUrl()
  {
    return $this->url;
  }
}

class Google_Service_AdSense_AdStyleFont extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $family;
  public $size;


  public function setFamily($family)
  {
    $this->family = $family;
  }
  public function getFamily()
  {
    return $this->family;
  }
  public function setSize($size)
  {
    $this->size = $size;
  }
  public function getSize()
  {
    return $this->size;
  }
}

class Google_Service_AdSense_AdUnit extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $code;
  protected $contentAdsSettingsType = 'Google_Service_AdSense_AdUnitContentAdsSettings';
  protected $contentAdsSettingsDataType = '';
  protected $customStyleType = 'Google_Service_AdSense_AdStyle';
  protected $customStyleDataType = '';
  protected $feedAdsSettingsType = 'Google_Service_AdSense_AdUnitFeedAdsSettings';
  protected $feedAdsSettingsDataType = '';
  public $id;
  public $kind;
  protected $mobileContentAdsSettingsType = 'Google_Service_AdSense_AdUnitMobileContentAdsSettings';
  protected $mobileContentAdsSettingsDataType = '';
  public $name;
  public $savedStyleId;
  public $status;


  public function setCode($code)
  {
    $this->code = $code;
  }
  public function getCode()
  {
    return $this->code;
  }
  public function setContentAdsSettings(Google_Service_AdSense_AdUnitContentAdsSettings $contentAdsSettings)
  {
    $this->contentAdsSettings = $contentAdsSettings;
  }
  public function getContentAdsSettings()
  {
    return $this->contentAdsSettings;
  }
  public function setCustomStyle(Google_Service_AdSense_AdStyle $customStyle)
  {
    $this->customStyle = $customStyle;
  }
  public function getCustomStyle()
  {
    return $this->customStyle;
  }
  public function setFeedAdsSettings(Google_Service_AdSense_AdUnitFeedAdsSettings $feedAdsSettings)
  {
    $this->feedAdsSettings = $feedAdsSettings;
  }
  public function getFeedAdsSettings()
  {
    return $this->feedAdsSettings;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setMobileContentAdsSettings(Google_Service_AdSense_AdUnitMobileContentAdsSettings $mobileContentAdsSettings)
  {
    $this->mobileContentAdsSettings = $mobileContentAdsSettings;
  }
  public function getMobileContentAdsSettings()
  {
    return $this->mobileContentAdsSettings;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setSavedStyleId($savedStyleId)
  {
    $this->savedStyleId = $savedStyleId;
  }
  public function getSavedStyleId()
  {
    return $this->savedStyleId;
  }
  public function setStatus($status)
  {
    $this->status = $status;
  }
  public function getStatus()
  {
    return $this->status;
  }
}

class Google_Service_AdSense_AdUnitContentAdsSettings extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $backupOptionType = 'Google_Service_AdSense_AdUnitContentAdsSettingsBackupOption';
  protected $backupOptionDataType = '';
  public $size;
  public $type;


  public function setBackupOption(Google_Service_AdSense_AdUnitContentAdsSettingsBackupOption $backupOption)
  {
    $this->backupOption = $backupOption;
  }
  public function getBackupOption()
  {
    return $this->backupOption;
  }
  public function setSize($size)
  {
    $this->size = $size;
  }
  public function getSize()
  {
    return $this->size;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_AdSense_AdUnitContentAdsSettingsBackupOption extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $color;
  public $type;
  public $url;


  public function setColor($color)
  {
    $this->color = $color;
  }
  public function getColor()
  {
    return $this->color;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUrl($url)
  {
    $this->url = $url;
  }
  public function getUrl()
  {
    return $this->url;
  }
}

class Google_Service_AdSense_AdUnitFeedAdsSettings extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $adPosition;
  public $frequency;
  public $minimumWordCount;
  public $type;


  public function setAdPosition($adPosition)
  {
    $this->adPosition = $adPosition;
  }
  public function getAdPosition()
  {
    return $this->adPosition;
  }
  public function setFrequency($frequency)
  {
    $this->frequency = $frequency;
  }
  public function getFrequency()
  {
    return $this->frequency;
  }
  public function setMinimumWordCount($minimumWordCount)
  {
    $this->minimumWordCount = $minimumWordCount;
  }
  public function getMinimumWordCount()
  {
    return $this->minimumWordCount;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_AdSense_AdUnitMobileContentAdsSettings extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $markupLanguage;
  public $scriptingLanguage;
  public $size;
  public $type;


  public function setMarkupLanguage($markupLanguage)
  {
    $this->markupLanguage = $markupLanguage;
  }
  public function getMarkupLanguage()
  {
    return $this->markupLanguage;
  }
  public function setScriptingLanguage($scriptingLanguage)
  {
    $this->scriptingLanguage = $scriptingLanguage;
  }
  public function getScriptingLanguage()
  {
    return $this->scriptingLanguage;
  }
  public function setSize($size)
  {
    $this->size = $size;
  }
  public function getSize()
  {
    return $this->size;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_AdSense_AdUnits extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_AdUnit';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}

class Google_Service_AdSense_AdsenseReportsGenerateResponse extends Google_Collection
{
  protected $collection_key = 'warnings';
  protected $internal_gapi_mappings = array(
  );
  public $averages;
  public $endDate;
  protected $headersType = 'Google_Service_AdSense_AdsenseReportsGenerateResponseHeaders';
  protected $headersDataType = 'array';
  public $kind;
  public $rows;
  public $startDate;
  public $totalMatchedRows;
  public $totals;
  public $warnings;


  public function setAverages($averages)
  {
    $this->averages = $averages;
  }
  public function getAverages()
  {
    return $this->averages;
  }
  public function setEndDate($endDate)
  {
    $this->endDate = $endDate;
  }
  public function getEndDate()
  {
    return $this->endDate;
  }
  public function setHeaders($headers)
  {
    $this->headers = $headers;
  }
  public function getHeaders()
  {
    return $this->headers;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setRows($rows)
  {
    $this->rows = $rows;
  }
  public function getRows()
  {
    return $this->rows;
  }
  public function setStartDate($startDate)
  {
    $this->startDate = $startDate;
  }
  public function getStartDate()
  {
    return $this->startDate;
  }
  public function setTotalMatchedRows($totalMatchedRows)
  {
    $this->totalMatchedRows = $totalMatchedRows;
  }
  public function getTotalMatchedRows()
  {
    return $this->totalMatchedRows;
  }
  public function setTotals($totals)
  {
    $this->totals = $totals;
  }
  public function getTotals()
  {
    return $this->totals;
  }
  public function setWarnings($warnings)
  {
    $this->warnings = $warnings;
  }
  public function getWarnings()
  {
    return $this->warnings;
  }
}

class Google_Service_AdSense_AdsenseReportsGenerateResponseHeaders extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $currency;
  public $name;
  public $type;


  public function setCurrency($currency)
  {
    $this->currency = $currency;
  }
  public function getCurrency()
  {
    return $this->currency;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_AdSense_Alert extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $isDismissible;
  public $kind;
  public $message;
  public $severity;
  public $type;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setIsDismissible($isDismissible)
  {
    $this->isDismissible = $isDismissible;
  }
  public function getIsDismissible()
  {
    return $this->isDismissible;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setMessage($message)
  {
    $this->message = $message;
  }
  public function getMessage()
  {
    return $this->message;
  }
  public function setSeverity($severity)
  {
    $this->severity = $severity;
  }
  public function getSeverity()
  {
    return $this->severity;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_AdSense_Alerts extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_AdSense_Alert';
  protected $itemsDataType = 'array';
  public $kind;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_AdSense_CustomChannel extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $code;
  public $id;
  public $kind;
  public $name;
  protected $targetingInfoType = 'Google_Service_AdSense_CustomChannelTargetingInfo';
  protected $targetingInfoDataType = '';


  public function setCode($code)
  {
    $this->code = $code;
  }
  public function getCode()
  {
    return $this->code;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setTargetingInfo(Google_Service_AdSense_CustomChannelTargetingInfo $targetingInfo)
  {
    $this->targetingInfo = $targetingInfo;
  }
  public function getTargetingInfo()
  {
    return $this->targetingInfo;
  }
}

class Google_Service_AdSense_CustomChannelTargetingInfo extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $adsAppearOn;
  public $description;
  public $location;
  public $siteLanguage;


  public function setAdsAppearOn($adsAppearOn)
  {
    $this->adsAppearOn = $adsAppearOn;
  }
  public function getAdsAppearOn()
  {
    return $this->adsAppearOn;
  }
  public function setDescription($description)
  {
    $this->description = $description;
  }
  public function getDescription()
  {
    return $this->description;
  }
  public function setLocation($location)
  {
    $this->location = $location;
  }
  public function getLocation()
  {
    return $this->location;
  }
  public function setSiteLanguage($siteLanguage)
  {
    $this->siteLanguage = $siteLanguage;
  }
  public function getSiteLanguage()
  {
    return $this->siteLanguage;
  }
}

class Google_Service_AdSense_CustomChannels extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_CustomChannel';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}

class Google_Service_AdSense_Metadata extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_AdSense_ReportingMetadataEntry';
  protected $itemsDataType = 'array';
  public $kind;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_AdSense_Payment extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $kind;
  public $paymentAmount;
  public $paymentAmountCurrencyCode;
  public $paymentDate;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setPaymentAmount($paymentAmount)
  {
    $this->paymentAmount = $paymentAmount;
  }
  public function getPaymentAmount()
  {
    return $this->paymentAmount;
  }
  public function setPaymentAmountCurrencyCode($paymentAmountCurrencyCode)
  {
    $this->paymentAmountCurrencyCode = $paymentAmountCurrencyCode;
  }
  public function getPaymentAmountCurrencyCode()
  {
    return $this->paymentAmountCurrencyCode;
  }
  public function setPaymentDate($paymentDate)
  {
    $this->paymentDate = $paymentDate;
  }
  public function getPaymentDate()
  {
    return $this->paymentDate;
  }
}

class Google_Service_AdSense_Payments extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_AdSense_Payment';
  protected $itemsDataType = 'array';
  public $kind;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_AdSense_ReportingMetadataEntry extends Google_Collection
{
  protected $collection_key = 'supportedProducts';
  protected $internal_gapi_mappings = array(
  );
  public $compatibleDimensions;
  public $compatibleMetrics;
  public $id;
  public $kind;
  public $requiredDimensions;
  public $requiredMetrics;
  public $supportedProducts;


  public function setCompatibleDimensions($compatibleDimensions)
  {
    $this->compatibleDimensions = $compatibleDimensions;
  }
  public function getCompatibleDimensions()
  {
    return $this->compatibleDimensions;
  }
  public function setCompatibleMetrics($compatibleMetrics)
  {
    $this->compatibleMetrics = $compatibleMetrics;
  }
  public function getCompatibleMetrics()
  {
    return $this->compatibleMetrics;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setRequiredDimensions($requiredDimensions)
  {
    $this->requiredDimensions = $requiredDimensions;
  }
  public function getRequiredDimensions()
  {
    return $this->requiredDimensions;
  }
  public function setRequiredMetrics($requiredMetrics)
  {
    $this->requiredMetrics = $requiredMetrics;
  }
  public function getRequiredMetrics()
  {
    return $this->requiredMetrics;
  }
  public function setSupportedProducts($supportedProducts)
  {
    $this->supportedProducts = $supportedProducts;
  }
  public function getSupportedProducts()
  {
    return $this->supportedProducts;
  }
}

class Google_Service_AdSense_SavedAdStyle extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $adStyleType = 'Google_Service_AdSense_AdStyle';
  protected $adStyleDataType = '';
  public $id;
  public $kind;
  public $name;


  public function setAdStyle(Google_Service_AdSense_AdStyle $adStyle)
  {
    $this->adStyle = $adStyle;
  }
  public function getAdStyle()
  {
    return $this->adStyle;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_AdSense_SavedAdStyles extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_SavedAdStyle';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}

class Google_Service_AdSense_SavedReport extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $kind;
  public $name;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_AdSense_SavedReports extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_SavedReport';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}

class Google_Service_AdSense_UrlChannel extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $kind;
  public $urlPattern;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setUrlPattern($urlPattern)
  {
    $this->urlPattern = $urlPattern;
  }
  public function getUrlPattern()
  {
    return $this->urlPattern;
  }
}

class Google_Service_AdSense_UrlChannels extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $etag;
  protected $itemsType = 'Google_Service_AdSense_UrlChannel';
  protected $itemsDataType = 'array';
  public $kind;
  public $nextPageToken;


  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextPageToken($nextPageToken)
  {
    $this->nextPageToken = $nextPageToken;
  }
  public function getNextPageToken()
  {
    return $this->nextPageToken;
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * Service definition for Admin (email_migration_v2).
 *
 * <p>
 * Email Migration API lets you migrate emails of users to Google backends.</p>
 *
 * <p>
 * For more information about this service, see the API
 * <a href="https://developers.google.com/admin-sdk/email-migration/v2/" target="_blank">Documentation</a>
 * </p>
 *
 * @author Google, Inc.
 */
class Google_Service_Admin extends Google_Service
{
  /** Manage email messages of users on your domain. */
  const EMAIL_MIGRATION =
      "https://www.googleapis.com/auth/email.migration";

  public $mail;
  

  /**
   * Constructs the internal representation of the Admin service.
   *
   * @param Google_Client $client
   */
  public function __construct(Google_Client $client)
  {
    parent::__construct($client);
    $this->servicePath = 'email/v2/users/';
    $this->version = 'email_migration_v2';
    $this->serviceName = 'admin';

    $this->mail = new Google_Service_Admin_Mail_Resource(
        $this,
        $this->serviceName,
        'mail',
        array(
          'methods' => array(
            'insert' => array(
              'path' => '{userKey}/mail',
              'httpMethod' => 'POST',
              'parameters' => array(
                'userKey' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
  }
}


/**
 * The "mail" collection of methods.
 * Typical usage is:
 *  <code>
 *   $adminService = new Google_Service_Admin(...);
 *   $mail = $adminService->mail;
 *  </code>
 */
class Google_Service_Admin_Mail_Resource extends Google_Service_Resource
{

  /**
   * Insert Mail into Google's Gmail backends (mail.insert)
   *
   * @param string $userKey The email or immutable id of the user
   * @param Google_MailItem $postBody
   * @param array $optParams Optional parameters.
   */
  public function insert($userKey, Google_Service_Admin_MailItem $postBody, $optParams = array())
  {
    $params = array('userKey' => $userKey, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params));
  }
}




class Google_Service_Admin_MailItem extends Google_Collection
{
  protected $collection_key = 'labels';
  protected $internal_gapi_mappings = array(
  );
  public $isDeleted;
  public $isDraft;
  public $isInbox;
  public $isSent;
  public $isStarred;
  public $isTrash;
  public $isUnread;
  public $kind;
  public $labels;


  public function setIsDeleted($isDeleted)
  {
    $this->isDeleted = $isDeleted;
  }
  public function getIsDeleted()
  {
    return $this->isDeleted;
  }
  public function setIsDraft($isDraft)
  {
    $this->isDraft = $isDraft;
  }
  public function getIsDraft()
  {
    return $this->isDraft;
  }
  public function setIsInbox($isInbox)
  {
    $this->isInbox = $isInbox;
  }
  public function getIsInbox()
  {
    return $this->isInbox;
  }
  public function setIsSent($isSent)
  {
    $this->isSent = $isSent;
  }
  public function getIsSent()
  {
    return $this->isSent;
  }
  public function setIsStarred($isStarred)
  {
    $this->isStarred = $isStarred;
  }
  public function getIsStarred()
  {
    return $this->isStarred;
  }
  public function setIsTrash($isTrash)
  {
    $this->isTrash = $isTrash;
  }
  public function getIsTrash()
  {
    return $this->isTrash;
  }
  public function setIsUnread($isUnread)
  {
    $this->isUnread = $isUnread;
  }
  public function getIsUnread()
  {
    return $this->isUnread;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setLabels($labels)
  {
    $this->labels = $labels;
  }
  public function getLabels()
  {
    return $this->labels;
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * Service definition for Analytics (v3).
 *
 * <p>
 * View and manage your Google Analytics data</p>
 *
 * <p>
 * For more information about this service, see the API
 * <a href="https://developers.google.com/analytics/" target="_blank">Documentation</a>
 * </p>
 *
 * @author Google, Inc.
 */
class Google_Service_Analytics extends Google_Service
{
  /** View and manage your Google Analytics data. */
  const ANALYTICS =
      "https://www.googleapis.com/auth/analytics";
  /** Edit Google Analytics management entities. */
  const ANALYTICS_EDIT =
      "https://www.googleapis.com/auth/analytics.edit";
  /** Manage Google Analytics Account users by email address. */
  const ANALYTICS_MANAGE_USERS =
      "https://www.googleapis.com/auth/analytics.manage.users";
  /** View Google Analytics user permissions. */
  const ANALYTICS_MANAGE_USERS_READONLY =
      "https://www.googleapis.com/auth/analytics.manage.users.readonly";
  /** Create a new Google Analytics account along with its default property and view. */
  const ANALYTICS_PROVISION =
      "https://www.googleapis.com/auth/analytics.provision";
  /** View your Google Analytics data. */
  const ANALYTICS_READONLY =
      "https://www.googleapis.com/auth/analytics.readonly";

  public $data_ga;
  public $data_mcf;
  public $data_realtime;
  public $management_accountSummaries;
  public $management_accountUserLinks;
  public $management_accounts;
  public $management_customDataSources;
  public $management_customDimensions;
  public $management_customMetrics;
  public $management_experiments;
  public $management_filters;
  public $management_goals;
  public $management_profileFilterLinks;
  public $management_profileUserLinks;
  public $management_profiles;
  public $management_segments;
  public $management_unsampledReports;
  public $management_uploads;
  public $management_webPropertyAdWordsLinks;
  public $management_webproperties;
  public $management_webpropertyUserLinks;
  public $metadata_columns;
  public $provisioning;
  

  /**
   * Constructs the internal representation of the Analytics service.
   *
   * @param Google_Client $client
   */
  public function __construct(Google_Client $client)
  {
    parent::__construct($client);
    $this->servicePath = 'analytics/v3/';
    $this->version = 'v3';
    $this->serviceName = 'analytics';

    $this->data_ga = new Google_Service_Analytics_DataGa_Resource(
        $this,
        $this->serviceName,
        'ga',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'data/ga',
              'httpMethod' => 'GET',
              'parameters' => array(
                'ids' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'start-date' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'end-date' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'metrics' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'sort' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'dimensions' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'segment' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'samplingLevel' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'filters' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'output' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
    $this->data_mcf = new Google_Service_Analytics_DataMcf_Resource(
        $this,
        $this->serviceName,
        'mcf',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'data/mcf',
              'httpMethod' => 'GET',
              'parameters' => array(
                'ids' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'start-date' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'end-date' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'metrics' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'sort' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'dimensions' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'samplingLevel' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'filters' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
    $this->data_realtime = new Google_Service_Analytics_DataRealtime_Resource(
        $this,
        $this->serviceName,
        'realtime',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'data/realtime',
              'httpMethod' => 'GET',
              'parameters' => array(
                'ids' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'metrics' => array(
                  'location' => 'query',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'sort' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'dimensions' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'filters' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
    $this->management_accountSummaries = new Google_Service_Analytics_ManagementAccountSummaries_Resource(
        $this,
        $this->serviceName,
        'accountSummaries',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'management/accountSummaries',
              'httpMethod' => 'GET',
              'parameters' => array(
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->management_accountUserLinks = new Google_Service_Analytics_ManagementAccountUserLinks_Resource(
        $this,
        $this->serviceName,
        'accountUserLinks',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/entityUserLinks/{linkId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/entityUserLinks',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/entityUserLinks',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/entityUserLinks/{linkId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_accounts = new Google_Service_Analytics_ManagementAccounts_Resource(
        $this,
        $this->serviceName,
        'accounts',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'management/accounts',
              'httpMethod' => 'GET',
              'parameters' => array(
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->management_customDataSources = new Google_Service_Analytics_ManagementCustomDataSources_Resource(
        $this,
        $this->serviceName,
        'customDataSources',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->management_customDimensions = new Google_Service_Analytics_ManagementCustomDimensions_Resource(
        $this,
        $this->serviceName,
        'customDimensions',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDimensionId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDimensionId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'ignoreCustomDataSourceLinks' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDimensions/{customDimensionId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDimensionId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'ignoreCustomDataSourceLinks' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
              ),
            ),
          )
        )
    );
    $this->management_customMetrics = new Google_Service_Analytics_ManagementCustomMetrics_Resource(
        $this,
        $this->serviceName,
        'customMetrics',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customMetricId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customMetricId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'ignoreCustomDataSourceLinks' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customMetrics/{customMetricId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customMetricId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'ignoreCustomDataSourceLinks' => array(
                  'location' => 'query',
                  'type' => 'boolean',
                ),
              ),
            ),
          )
        )
    );
    $this->management_experiments = new Google_Service_Analytics_ManagementExperiments_Resource(
        $this,
        $this->serviceName,
        'experiments',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'experimentId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'experimentId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'experimentId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/experiments/{experimentId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'experimentId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_filters = new Google_Service_Analytics_ManagementFilters_Resource(
        $this,
        $this->serviceName,
        'filters',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/filters/{filterId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'filterId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'get' => array(
              'path' => 'management/accounts/{accountId}/filters/{filterId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'filterId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/filters',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/filters',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/filters/{filterId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'filterId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/filters/{filterId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'filterId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_goals = new Google_Service_Analytics_ManagementGoals_Resource(
        $this,
        $this->serviceName,
        'goals',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'goalId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'goalId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/goals/{goalId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'goalId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_profileFilterLinks = new Google_Service_Analytics_ManagementProfileFilterLinks_Resource(
        $this,
        $this->serviceName,
        'profileFilterLinks',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/profileFilterLinks/{linkId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_profileUserLinks = new Google_Service_Analytics_ManagementProfileUserLinks_Resource(
        $this,
        $this->serviceName,
        'profileUserLinks',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks/{linkId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/entityUserLinks/{linkId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_profiles = new Google_Service_Analytics_ManagementProfiles_Resource(
        $this,
        $this->serviceName,
        'profiles',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_segments = new Google_Service_Analytics_ManagementSegments_Resource(
        $this,
        $this->serviceName,
        'segments',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'management/segments',
              'httpMethod' => 'GET',
              'parameters' => array(
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->management_unsampledReports = new Google_Service_Analytics_ManagementUnsampledReports_Resource(
        $this,
        $this->serviceName,
        'unsampledReports',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports/{unsampledReportId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'unsampledReportId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/profiles/{profileId}/unsampledReports',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'profileId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),
          )
        )
    );
    $this->management_uploads = new Google_Service_Analytics_ManagementUploads_Resource(
        $this,
        $this->serviceName,
        'uploads',
        array(
          'methods' => array(
            'deleteUploadData' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/deleteUploadData',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDataSourceId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads/{uploadId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDataSourceId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'uploadId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDataSourceId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'uploadData' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/customDataSources/{customDataSourceId}/uploads',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'customDataSourceId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_webPropertyAdWordsLinks = new Google_Service_Analytics_ManagementWebPropertyAdWordsLinks_Resource(
        $this,
        $this->serviceName,
        'webPropertyAdWordsLinks',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyAdWordsLinkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyAdWordsLinkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyAdWordsLinkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityAdWordsLinks/{webPropertyAdWordsLinkId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyAdWordsLinkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_webproperties = new Google_Service_Analytics_ManagementWebproperties_Resource(
        $this,
        $this->serviceName,
        'webproperties',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'patch' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}',
              'httpMethod' => 'PATCH',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->management_webpropertyUserLinks = new Google_Service_Analytics_ManagementWebpropertyUserLinks_Resource(
        $this,
        $this->serviceName,
        'webpropertyUserLinks',
        array(
          'methods' => array(
            'delete' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks/{linkId}',
              'httpMethod' => 'DELETE',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'insert' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks',
              'httpMethod' => 'POST',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),'list' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks',
              'httpMethod' => 'GET',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'max-results' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
                'start-index' => array(
                  'location' => 'query',
                  'type' => 'integer',
                ),
              ),
            ),'update' => array(
              'path' => 'management/accounts/{accountId}/webproperties/{webPropertyId}/entityUserLinks/{linkId}',
              'httpMethod' => 'PUT',
              'parameters' => array(
                'accountId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'webPropertyId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
                'linkId' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->metadata_columns = new Google_Service_Analytics_MetadataColumns_Resource(
        $this,
        $this->serviceName,
        'columns',
        array(
          'methods' => array(
            'list' => array(
              'path' => 'metadata/{reportType}/columns',
              'httpMethod' => 'GET',
              'parameters' => array(
                'reportType' => array(
                  'location' => 'path',
                  'type' => 'string',
                  'required' => true,
                ),
              ),
            ),
          )
        )
    );
    $this->provisioning = new Google_Service_Analytics_Provisioning_Resource(
        $this,
        $this->serviceName,
        'provisioning',
        array(
          'methods' => array(
            'createAccountTicket' => array(
              'path' => 'provisioning/createAccountTicket',
              'httpMethod' => 'POST',
              'parameters' => array(),
            ),
          )
        )
    );
  }
}


/**
 * The "data" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $data = $analyticsService->data;
 *  </code>
 */
class Google_Service_Analytics_Data_Resource extends Google_Service_Resource
{
}

/**
 * The "ga" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $ga = $analyticsService->ga;
 *  </code>
 */
class Google_Service_Analytics_DataGa_Resource extends Google_Service_Resource
{

  /**
   * Returns Analytics data for a view (profile). (ga.get)
   *
   * @param string $ids Unique table ID for retrieving Analytics data. Table ID is
   * of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.
   * @param string $startDate Start date for fetching Analytics data. Requests can
   * specify a start date formatted as YYYY-MM-DD, or as a relative date (e.g.,
   * today, yesterday, or 7daysAgo). The default value is 7daysAgo.
   * @param string $endDate End date for fetching Analytics data. Request can
   * should specify an end date formatted as YYYY-MM-DD, or as a relative date
   * (e.g., today, yesterday, or 7daysAgo). The default value is yesterday.
   * @param string $metrics A comma-separated list of Analytics metrics. E.g.,
   * 'ga:sessions,ga:pageviews'. At least one metric must be specified.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of entries to include in this
   * feed.
   * @opt_param string sort A comma-separated list of dimensions or metrics that
   * determine the sort order for Analytics data.
   * @opt_param string dimensions A comma-separated list of Analytics dimensions.
   * E.g., 'ga:browser,ga:city'.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @opt_param string segment An Analytics segment to be applied to data.
   * @opt_param string samplingLevel The desired sampling level.
   * @opt_param string filters A comma-separated list of dimension or metric
   * filters to be applied to Analytics data.
   * @opt_param string output The selected format for the response. Default format
   * is JSON.
   * @return Google_Service_Analytics_GaData
   */
  public function get($ids, $startDate, $endDate, $metrics, $optParams = array())
  {
    $params = array('ids' => $ids, 'start-date' => $startDate, 'end-date' => $endDate, 'metrics' => $metrics);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_GaData");
  }
}
/**
 * The "mcf" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $mcf = $analyticsService->mcf;
 *  </code>
 */
class Google_Service_Analytics_DataMcf_Resource extends Google_Service_Resource
{

  /**
   * Returns Analytics Multi-Channel Funnels data for a view (profile). (mcf.get)
   *
   * @param string $ids Unique table ID for retrieving Analytics data. Table ID is
   * of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.
   * @param string $startDate Start date for fetching Analytics data. Requests can
   * specify a start date formatted as YYYY-MM-DD, or as a relative date (e.g.,
   * today, yesterday, or 7daysAgo). The default value is 7daysAgo.
   * @param string $endDate End date for fetching Analytics data. Requests can
   * specify a start date formatted as YYYY-MM-DD, or as a relative date (e.g.,
   * today, yesterday, or 7daysAgo). The default value is 7daysAgo.
   * @param string $metrics A comma-separated list of Multi-Channel Funnels
   * metrics. E.g., 'mcf:totalConversions,mcf:totalConversionValue'. At least one
   * metric must be specified.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of entries to include in this
   * feed.
   * @opt_param string sort A comma-separated list of dimensions or metrics that
   * determine the sort order for the Analytics data.
   * @opt_param string dimensions A comma-separated list of Multi-Channel Funnels
   * dimensions. E.g., 'mcf:source,mcf:medium'.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @opt_param string samplingLevel The desired sampling level.
   * @opt_param string filters A comma-separated list of dimension or metric
   * filters to be applied to the Analytics data.
   * @return Google_Service_Analytics_McfData
   */
  public function get($ids, $startDate, $endDate, $metrics, $optParams = array())
  {
    $params = array('ids' => $ids, 'start-date' => $startDate, 'end-date' => $endDate, 'metrics' => $metrics);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_McfData");
  }
}
/**
 * The "realtime" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $realtime = $analyticsService->realtime;
 *  </code>
 */
class Google_Service_Analytics_DataRealtime_Resource extends Google_Service_Resource
{

  /**
   * Returns real time data for a view (profile). (realtime.get)
   *
   * @param string $ids Unique table ID for retrieving real time data. Table ID is
   * of the form ga:XXXX, where XXXX is the Analytics view (profile) ID.
   * @param string $metrics A comma-separated list of real time metrics. E.g.,
   * 'rt:activeUsers'. At least one metric must be specified.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of entries to include in this
   * feed.
   * @opt_param string sort A comma-separated list of dimensions or metrics that
   * determine the sort order for real time data.
   * @opt_param string dimensions A comma-separated list of real time dimensions.
   * E.g., 'rt:medium,rt:city'.
   * @opt_param string filters A comma-separated list of dimension or metric
   * filters to be applied to real time data.
   * @return Google_Service_Analytics_RealtimeData
   */
  public function get($ids, $metrics, $optParams = array())
  {
    $params = array('ids' => $ids, 'metrics' => $metrics);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_RealtimeData");
  }
}

/**
 * The "management" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $management = $analyticsService->management;
 *  </code>
 */
class Google_Service_Analytics_Management_Resource extends Google_Service_Resource
{
}

/**
 * The "accountSummaries" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $accountSummaries = $analyticsService->accountSummaries;
 *  </code>
 */
class Google_Service_Analytics_ManagementAccountSummaries_Resource extends Google_Service_Resource
{

  /**
   * Lists account summaries (lightweight tree comprised of
   * accounts/properties/profiles) to which the user has access.
   * (accountSummaries.listManagementAccountSummaries)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of account summaries to include
   * in this response, where the largest acceptable value is 1000.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_AccountSummaries
   */
  public function listManagementAccountSummaries($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_AccountSummaries");
  }
}
/**
 * The "accountUserLinks" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $accountUserLinks = $analyticsService->accountUserLinks;
 *  </code>
 */
class Google_Service_Analytics_ManagementAccountUserLinks_Resource extends Google_Service_Resource
{

  /**
   * Removes a user from the given account. (accountUserLinks.delete)
   *
   * @param string $accountId Account ID to delete the user link for.
   * @param string $linkId Link ID to delete the user link for.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $linkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'linkId' => $linkId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Adds a new user to the given account. (accountUserLinks.insert)
   *
   * @param string $accountId Account ID to create the user link for.
   * @param Google_EntityUserLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityUserLink
   */
  public function insert($accountId, Google_Service_Analytics_EntityUserLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_EntityUserLink");
  }

  /**
   * Lists account-user links for a given account.
   * (accountUserLinks.listManagementAccountUserLinks)
   *
   * @param string $accountId Account ID to retrieve the user links for.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of account-user links to
   * include in this response.
   * @opt_param int start-index An index of the first account-user link to
   * retrieve. Use this parameter as a pagination mechanism along with the max-
   * results parameter.
   * @return Google_Service_Analytics_EntityUserLinks
   */
  public function listManagementAccountUserLinks($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_EntityUserLinks");
  }

  /**
   * Updates permissions for an existing user on the given account.
   * (accountUserLinks.update)
   *
   * @param string $accountId Account ID to update the account-user link for.
   * @param string $linkId Link ID to update the account-user link for.
   * @param Google_EntityUserLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityUserLink
   */
  public function update($accountId, $linkId, Google_Service_Analytics_EntityUserLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'linkId' => $linkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_EntityUserLink");
  }
}
/**
 * The "accounts" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $accounts = $analyticsService->accounts;
 *  </code>
 */
class Google_Service_Analytics_ManagementAccounts_Resource extends Google_Service_Resource
{

  /**
   * Lists all accounts to which the user has access.
   * (accounts.listManagementAccounts)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of accounts to include in this
   * response.
   * @opt_param int start-index An index of the first account to retrieve. Use
   * this parameter as a pagination mechanism along with the max-results
   * parameter.
   * @return Google_Service_Analytics_Accounts
   */
  public function listManagementAccounts($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Accounts");
  }
}
/**
 * The "customDataSources" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $customDataSources = $analyticsService->customDataSources;
 *  </code>
 */
class Google_Service_Analytics_ManagementCustomDataSources_Resource extends Google_Service_Resource
{

  /**
   * List custom data sources to which the user has access.
   * (customDataSources.listManagementCustomDataSources)
   *
   * @param string $accountId Account Id for the custom data sources to retrieve.
   * @param string $webPropertyId Web property Id for the custom data sources to
   * retrieve.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of custom data sources to
   * include in this response.
   * @opt_param int start-index A 1-based index of the first custom data source to
   * retrieve. Use this parameter as a pagination mechanism along with the max-
   * results parameter.
   * @return Google_Service_Analytics_CustomDataSources
   */
  public function listManagementCustomDataSources($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_CustomDataSources");
  }
}
/**
 * The "customDimensions" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $customDimensions = $analyticsService->customDimensions;
 *  </code>
 */
class Google_Service_Analytics_ManagementCustomDimensions_Resource extends Google_Service_Resource
{

  /**
   * Get a custom dimension to which the user has access. (customDimensions.get)
   *
   * @param string $accountId Account ID for the custom dimension to retrieve.
   * @param string $webPropertyId Web property ID for the custom dimension to
   * retrieve.
   * @param string $customDimensionId The ID of the custom dimension to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_CustomDimension
   */
  public function get($accountId, $webPropertyId, $customDimensionId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDimensionId' => $customDimensionId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_CustomDimension");
  }

  /**
   * Create a new custom dimension. (customDimensions.insert)
   *
   * @param string $accountId Account ID for the custom dimension to create.
   * @param string $webPropertyId Web property ID for the custom dimension to
   * create.
   * @param Google_CustomDimension $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_CustomDimension
   */
  public function insert($accountId, $webPropertyId, Google_Service_Analytics_CustomDimension $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_CustomDimension");
  }

  /**
   * Lists custom dimensions to which the user has access.
   * (customDimensions.listManagementCustomDimensions)
   *
   * @param string $accountId Account ID for the custom dimensions to retrieve.
   * @param string $webPropertyId Web property ID for the custom dimensions to
   * retrieve.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of custom dimensions to include
   * in this response.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_CustomDimensions
   */
  public function listManagementCustomDimensions($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_CustomDimensions");
  }

  /**
   * Updates an existing custom dimension. This method supports patch semantics.
   * (customDimensions.patch)
   *
   * @param string $accountId Account ID for the custom dimension to update.
   * @param string $webPropertyId Web property ID for the custom dimension to
   * update.
   * @param string $customDimensionId Custom dimension ID for the custom dimension
   * to update.
   * @param Google_CustomDimension $postBody
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool ignoreCustomDataSourceLinks Force the update and ignore any
   * warnings related to the custom dimension being linked to a custom data source
   * / data set.
   * @return Google_Service_Analytics_CustomDimension
   */
  public function patch($accountId, $webPropertyId, $customDimensionId, Google_Service_Analytics_CustomDimension $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDimensionId' => $customDimensionId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_CustomDimension");
  }

  /**
   * Updates an existing custom dimension. (customDimensions.update)
   *
   * @param string $accountId Account ID for the custom dimension to update.
   * @param string $webPropertyId Web property ID for the custom dimension to
   * update.
   * @param string $customDimensionId Custom dimension ID for the custom dimension
   * to update.
   * @param Google_CustomDimension $postBody
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool ignoreCustomDataSourceLinks Force the update and ignore any
   * warnings related to the custom dimension being linked to a custom data source
   * / data set.
   * @return Google_Service_Analytics_CustomDimension
   */
  public function update($accountId, $webPropertyId, $customDimensionId, Google_Service_Analytics_CustomDimension $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDimensionId' => $customDimensionId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_CustomDimension");
  }
}
/**
 * The "customMetrics" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $customMetrics = $analyticsService->customMetrics;
 *  </code>
 */
class Google_Service_Analytics_ManagementCustomMetrics_Resource extends Google_Service_Resource
{

  /**
   * Get a custom metric to which the user has access. (customMetrics.get)
   *
   * @param string $accountId Account ID for the custom metric to retrieve.
   * @param string $webPropertyId Web property ID for the custom metric to
   * retrieve.
   * @param string $customMetricId The ID of the custom metric to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_CustomMetric
   */
  public function get($accountId, $webPropertyId, $customMetricId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customMetricId' => $customMetricId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_CustomMetric");
  }

  /**
   * Create a new custom metric. (customMetrics.insert)
   *
   * @param string $accountId Account ID for the custom metric to create.
   * @param string $webPropertyId Web property ID for the custom dimension to
   * create.
   * @param Google_CustomMetric $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_CustomMetric
   */
  public function insert($accountId, $webPropertyId, Google_Service_Analytics_CustomMetric $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_CustomMetric");
  }

  /**
   * Lists custom metrics to which the user has access.
   * (customMetrics.listManagementCustomMetrics)
   *
   * @param string $accountId Account ID for the custom metrics to retrieve.
   * @param string $webPropertyId Web property ID for the custom metrics to
   * retrieve.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of custom metrics to include in
   * this response.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_CustomMetrics
   */
  public function listManagementCustomMetrics($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_CustomMetrics");
  }

  /**
   * Updates an existing custom metric. This method supports patch semantics.
   * (customMetrics.patch)
   *
   * @param string $accountId Account ID for the custom metric to update.
   * @param string $webPropertyId Web property ID for the custom metric to update.
   * @param string $customMetricId Custom metric ID for the custom metric to
   * update.
   * @param Google_CustomMetric $postBody
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool ignoreCustomDataSourceLinks Force the update and ignore any
   * warnings related to the custom metric being linked to a custom data source /
   * data set.
   * @return Google_Service_Analytics_CustomMetric
   */
  public function patch($accountId, $webPropertyId, $customMetricId, Google_Service_Analytics_CustomMetric $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customMetricId' => $customMetricId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_CustomMetric");
  }

  /**
   * Updates an existing custom metric. (customMetrics.update)
   *
   * @param string $accountId Account ID for the custom metric to update.
   * @param string $webPropertyId Web property ID for the custom metric to update.
   * @param string $customMetricId Custom metric ID for the custom metric to
   * update.
   * @param Google_CustomMetric $postBody
   * @param array $optParams Optional parameters.
   *
   * @opt_param bool ignoreCustomDataSourceLinks Force the update and ignore any
   * warnings related to the custom metric being linked to a custom data source /
   * data set.
   * @return Google_Service_Analytics_CustomMetric
   */
  public function update($accountId, $webPropertyId, $customMetricId, Google_Service_Analytics_CustomMetric $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customMetricId' => $customMetricId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_CustomMetric");
  }
}
/**
 * The "experiments" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $experiments = $analyticsService->experiments;
 *  </code>
 */
class Google_Service_Analytics_ManagementExperiments_Resource extends Google_Service_Resource
{

  /**
   * Delete an experiment. (experiments.delete)
   *
   * @param string $accountId Account ID to which the experiment belongs
   * @param string $webPropertyId Web property ID to which the experiment belongs
   * @param string $profileId View (Profile) ID to which the experiment belongs
   * @param string $experimentId ID of the experiment to delete
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $webPropertyId, $profileId, $experimentId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'experimentId' => $experimentId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Returns an experiment to which the user has access. (experiments.get)
   *
   * @param string $accountId Account ID to retrieve the experiment for.
   * @param string $webPropertyId Web property ID to retrieve the experiment for.
   * @param string $profileId View (Profile) ID to retrieve the experiment for.
   * @param string $experimentId Experiment ID to retrieve the experiment for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Experiment
   */
  public function get($accountId, $webPropertyId, $profileId, $experimentId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'experimentId' => $experimentId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_Experiment");
  }

  /**
   * Create a new experiment. (experiments.insert)
   *
   * @param string $accountId Account ID to create the experiment for.
   * @param string $webPropertyId Web property ID to create the experiment for.
   * @param string $profileId View (Profile) ID to create the experiment for.
   * @param Google_Experiment $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Experiment
   */
  public function insert($accountId, $webPropertyId, $profileId, Google_Service_Analytics_Experiment $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_Experiment");
  }

  /**
   * Lists experiments to which the user has access.
   * (experiments.listManagementExperiments)
   *
   * @param string $accountId Account ID to retrieve experiments for.
   * @param string $webPropertyId Web property ID to retrieve experiments for.
   * @param string $profileId View (Profile) ID to retrieve experiments for.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of experiments to include in
   * this response.
   * @opt_param int start-index An index of the first experiment to retrieve. Use
   * this parameter as a pagination mechanism along with the max-results
   * parameter.
   * @return Google_Service_Analytics_Experiments
   */
  public function listManagementExperiments($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Experiments");
  }

  /**
   * Update an existing experiment. This method supports patch semantics.
   * (experiments.patch)
   *
   * @param string $accountId Account ID of the experiment to update.
   * @param string $webPropertyId Web property ID of the experiment to update.
   * @param string $profileId View (Profile) ID of the experiment to update.
   * @param string $experimentId Experiment ID of the experiment to update.
   * @param Google_Experiment $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Experiment
   */
  public function patch($accountId, $webPropertyId, $profileId, $experimentId, Google_Service_Analytics_Experiment $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'experimentId' => $experimentId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_Experiment");
  }

  /**
   * Update an existing experiment. (experiments.update)
   *
   * @param string $accountId Account ID of the experiment to update.
   * @param string $webPropertyId Web property ID of the experiment to update.
   * @param string $profileId View (Profile) ID of the experiment to update.
   * @param string $experimentId Experiment ID of the experiment to update.
   * @param Google_Experiment $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Experiment
   */
  public function update($accountId, $webPropertyId, $profileId, $experimentId, Google_Service_Analytics_Experiment $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'experimentId' => $experimentId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_Experiment");
  }
}
/**
 * The "filters" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $filters = $analyticsService->filters;
 *  </code>
 */
class Google_Service_Analytics_ManagementFilters_Resource extends Google_Service_Resource
{

  /**
   * Delete a filter. (filters.delete)
   *
   * @param string $accountId Account ID to delete the filter for.
   * @param string $filterId ID of the filter to be deleted.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Filter
   */
  public function delete($accountId, $filterId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'filterId' => $filterId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params), "Google_Service_Analytics_Filter");
  }

  /**
   * Returns a filters to which the user has access. (filters.get)
   *
   * @param string $accountId Account ID to retrieve filters for.
   * @param string $filterId Filter ID to retrieve filters for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Filter
   */
  public function get($accountId, $filterId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'filterId' => $filterId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_Filter");
  }

  /**
   * Create a new filter. (filters.insert)
   *
   * @param string $accountId Account ID to create filter for.
   * @param Google_Filter $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Filter
   */
  public function insert($accountId, Google_Service_Analytics_Filter $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_Filter");
  }

  /**
   * Lists all filters for an account (filters.listManagementFilters)
   *
   * @param string $accountId Account ID to retrieve filters for.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of filters to include in this
   * response.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_Filters
   */
  public function listManagementFilters($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Filters");
  }

  /**
   * Updates an existing filter. This method supports patch semantics.
   * (filters.patch)
   *
   * @param string $accountId Account ID to which the filter belongs.
   * @param string $filterId ID of the filter to be updated.
   * @param Google_Filter $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Filter
   */
  public function patch($accountId, $filterId, Google_Service_Analytics_Filter $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'filterId' => $filterId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_Filter");
  }

  /**
   * Updates an existing filter. (filters.update)
   *
   * @param string $accountId Account ID to which the filter belongs.
   * @param string $filterId ID of the filter to be updated.
   * @param Google_Filter $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Filter
   */
  public function update($accountId, $filterId, Google_Service_Analytics_Filter $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'filterId' => $filterId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_Filter");
  }
}
/**
 * The "goals" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $goals = $analyticsService->goals;
 *  </code>
 */
class Google_Service_Analytics_ManagementGoals_Resource extends Google_Service_Resource
{

  /**
   * Gets a goal to which the user has access. (goals.get)
   *
   * @param string $accountId Account ID to retrieve the goal for.
   * @param string $webPropertyId Web property ID to retrieve the goal for.
   * @param string $profileId View (Profile) ID to retrieve the goal for.
   * @param string $goalId Goal ID to retrieve the goal for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Goal
   */
  public function get($accountId, $webPropertyId, $profileId, $goalId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'goalId' => $goalId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_Goal");
  }

  /**
   * Create a new goal. (goals.insert)
   *
   * @param string $accountId Account ID to create the goal for.
   * @param string $webPropertyId Web property ID to create the goal for.
   * @param string $profileId View (Profile) ID to create the goal for.
   * @param Google_Goal $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Goal
   */
  public function insert($accountId, $webPropertyId, $profileId, Google_Service_Analytics_Goal $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_Goal");
  }

  /**
   * Lists goals to which the user has access. (goals.listManagementGoals)
   *
   * @param string $accountId Account ID to retrieve goals for. Can either be a
   * specific account ID or '~all', which refers to all the accounts that user has
   * access to.
   * @param string $webPropertyId Web property ID to retrieve goals for. Can
   * either be a specific web property ID or '~all', which refers to all the web
   * properties that user has access to.
   * @param string $profileId View (Profile) ID to retrieve goals for. Can either
   * be a specific view (profile) ID or '~all', which refers to all the views
   * (profiles) that user has access to.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of goals to include in this
   * response.
   * @opt_param int start-index An index of the first goal to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_Goals
   */
  public function listManagementGoals($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Goals");
  }

  /**
   * Updates an existing view (profile). This method supports patch semantics.
   * (goals.patch)
   *
   * @param string $accountId Account ID to update the goal.
   * @param string $webPropertyId Web property ID to update the goal.
   * @param string $profileId View (Profile) ID to update the goal.
   * @param string $goalId Index of the goal to be updated.
   * @param Google_Goal $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Goal
   */
  public function patch($accountId, $webPropertyId, $profileId, $goalId, Google_Service_Analytics_Goal $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'goalId' => $goalId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_Goal");
  }

  /**
   * Updates an existing view (profile). (goals.update)
   *
   * @param string $accountId Account ID to update the goal.
   * @param string $webPropertyId Web property ID to update the goal.
   * @param string $profileId View (Profile) ID to update the goal.
   * @param string $goalId Index of the goal to be updated.
   * @param Google_Goal $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Goal
   */
  public function update($accountId, $webPropertyId, $profileId, $goalId, Google_Service_Analytics_Goal $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'goalId' => $goalId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_Goal");
  }
}
/**
 * The "profileFilterLinks" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $profileFilterLinks = $analyticsService->profileFilterLinks;
 *  </code>
 */
class Google_Service_Analytics_ManagementProfileFilterLinks_Resource extends Google_Service_Resource
{

  /**
   * Delete a profile filter link. (profileFilterLinks.delete)
   *
   * @param string $accountId Account ID to which the profile filter link belongs.
   * @param string $webPropertyId Web property Id to which the profile filter link
   * belongs.
   * @param string $profileId Profile ID to which the filter link belongs.
   * @param string $linkId ID of the profile filter link to delete.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $webPropertyId, $profileId, $linkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'linkId' => $linkId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Returns a single profile filter link. (profileFilterLinks.get)
   *
   * @param string $accountId Account ID to retrieve profile filter link for.
   * @param string $webPropertyId Web property Id to retrieve profile filter link
   * for.
   * @param string $profileId Profile ID to retrieve filter link for.
   * @param string $linkId ID of the profile filter link.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_ProfileFilterLink
   */
  public function get($accountId, $webPropertyId, $profileId, $linkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'linkId' => $linkId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_ProfileFilterLink");
  }

  /**
   * Create a new profile filter link. (profileFilterLinks.insert)
   *
   * @param string $accountId Account ID to create profile filter link for.
   * @param string $webPropertyId Web property Id to create profile filter link
   * for.
   * @param string $profileId Profile ID to create filter link for.
   * @param Google_ProfileFilterLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_ProfileFilterLink
   */
  public function insert($accountId, $webPropertyId, $profileId, Google_Service_Analytics_ProfileFilterLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_ProfileFilterLink");
  }

  /**
   * Lists all profile filter links for a profile.
   * (profileFilterLinks.listManagementProfileFilterLinks)
   *
   * @param string $accountId Account ID to retrieve profile filter links for.
   * @param string $webPropertyId Web property Id for profile filter links for.
   * Can either be a specific web property ID or '~all', which refers to all the
   * web properties that user has access to.
   * @param string $profileId Profile ID to retrieve filter links for. Can either
   * be a specific profile ID or '~all', which refers to all the profiles that
   * user has access to.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of profile filter links to
   * include in this response.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_ProfileFilterLinks
   */
  public function listManagementProfileFilterLinks($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_ProfileFilterLinks");
  }

  /**
   * Update an existing profile filter link. This method supports patch semantics.
   * (profileFilterLinks.patch)
   *
   * @param string $accountId Account ID to which profile filter link belongs.
   * @param string $webPropertyId Web property Id to which profile filter link
   * belongs
   * @param string $profileId Profile ID to which filter link belongs
   * @param string $linkId ID of the profile filter link to be updated.
   * @param Google_ProfileFilterLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_ProfileFilterLink
   */
  public function patch($accountId, $webPropertyId, $profileId, $linkId, Google_Service_Analytics_ProfileFilterLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'linkId' => $linkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_ProfileFilterLink");
  }

  /**
   * Update an existing profile filter link. (profileFilterLinks.update)
   *
   * @param string $accountId Account ID to which profile filter link belongs.
   * @param string $webPropertyId Web property Id to which profile filter link
   * belongs
   * @param string $profileId Profile ID to which filter link belongs
   * @param string $linkId ID of the profile filter link to be updated.
   * @param Google_ProfileFilterLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_ProfileFilterLink
   */
  public function update($accountId, $webPropertyId, $profileId, $linkId, Google_Service_Analytics_ProfileFilterLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'linkId' => $linkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_ProfileFilterLink");
  }
}
/**
 * The "profileUserLinks" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $profileUserLinks = $analyticsService->profileUserLinks;
 *  </code>
 */
class Google_Service_Analytics_ManagementProfileUserLinks_Resource extends Google_Service_Resource
{

  /**
   * Removes a user from the given view (profile). (profileUserLinks.delete)
   *
   * @param string $accountId Account ID to delete the user link for.
   * @param string $webPropertyId Web Property ID to delete the user link for.
   * @param string $profileId View (Profile) ID to delete the user link for.
   * @param string $linkId Link ID to delete the user link for.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $webPropertyId, $profileId, $linkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'linkId' => $linkId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Adds a new user to the given view (profile). (profileUserLinks.insert)
   *
   * @param string $accountId Account ID to create the user link for.
   * @param string $webPropertyId Web Property ID to create the user link for.
   * @param string $profileId View (Profile) ID to create the user link for.
   * @param Google_EntityUserLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityUserLink
   */
  public function insert($accountId, $webPropertyId, $profileId, Google_Service_Analytics_EntityUserLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_EntityUserLink");
  }

  /**
   * Lists profile-user links for a given view (profile).
   * (profileUserLinks.listManagementProfileUserLinks)
   *
   * @param string $accountId Account ID which the given view (profile) belongs
   * to.
   * @param string $webPropertyId Web Property ID which the given view (profile)
   * belongs to. Can either be a specific web property ID or '~all', which refers
   * to all the web properties that user has access to.
   * @param string $profileId View (Profile) ID to retrieve the profile-user links
   * for. Can either be a specific profile ID or '~all', which refers to all the
   * profiles that user has access to.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of profile-user links to
   * include in this response.
   * @opt_param int start-index An index of the first profile-user link to
   * retrieve. Use this parameter as a pagination mechanism along with the max-
   * results parameter.
   * @return Google_Service_Analytics_EntityUserLinks
   */
  public function listManagementProfileUserLinks($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_EntityUserLinks");
  }

  /**
   * Updates permissions for an existing user on the given view (profile).
   * (profileUserLinks.update)
   *
   * @param string $accountId Account ID to update the user link for.
   * @param string $webPropertyId Web Property ID to update the user link for.
   * @param string $profileId View (Profile ID) to update the user link for.
   * @param string $linkId Link ID to update the user link for.
   * @param Google_EntityUserLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityUserLink
   */
  public function update($accountId, $webPropertyId, $profileId, $linkId, Google_Service_Analytics_EntityUserLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'linkId' => $linkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_EntityUserLink");
  }
}
/**
 * The "profiles" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $profiles = $analyticsService->profiles;
 *  </code>
 */
class Google_Service_Analytics_ManagementProfiles_Resource extends Google_Service_Resource
{

  /**
   * Deletes a view (profile). (profiles.delete)
   *
   * @param string $accountId Account ID to delete the view (profile) for.
   * @param string $webPropertyId Web property ID to delete the view (profile)
   * for.
   * @param string $profileId ID of the view (profile) to be deleted.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Gets a view (profile) to which the user has access. (profiles.get)
   *
   * @param string $accountId Account ID to retrieve the goal for.
   * @param string $webPropertyId Web property ID to retrieve the goal for.
   * @param string $profileId View (Profile) ID to retrieve the goal for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Profile
   */
  public function get($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_Profile");
  }

  /**
   * Create a new view (profile). (profiles.insert)
   *
   * @param string $accountId Account ID to create the view (profile) for.
   * @param string $webPropertyId Web property ID to create the view (profile)
   * for.
   * @param Google_Profile $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Profile
   */
  public function insert($accountId, $webPropertyId, Google_Service_Analytics_Profile $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_Profile");
  }

  /**
   * Lists views (profiles) to which the user has access.
   * (profiles.listManagementProfiles)
   *
   * @param string $accountId Account ID for the view (profiles) to retrieve. Can
   * either be a specific account ID or '~all', which refers to all the accounts
   * to which the user has access.
   * @param string $webPropertyId Web property ID for the views (profiles) to
   * retrieve. Can either be a specific web property ID or '~all', which refers to
   * all the web properties to which the user has access.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of views (profiles) to include
   * in this response.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_Profiles
   */
  public function listManagementProfiles($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Profiles");
  }

  /**
   * Updates an existing view (profile). This method supports patch semantics.
   * (profiles.patch)
   *
   * @param string $accountId Account ID to which the view (profile) belongs
   * @param string $webPropertyId Web property ID to which the view (profile)
   * belongs
   * @param string $profileId ID of the view (profile) to be updated.
   * @param Google_Profile $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Profile
   */
  public function patch($accountId, $webPropertyId, $profileId, Google_Service_Analytics_Profile $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_Profile");
  }

  /**
   * Updates an existing view (profile). (profiles.update)
   *
   * @param string $accountId Account ID to which the view (profile) belongs
   * @param string $webPropertyId Web property ID to which the view (profile)
   * belongs
   * @param string $profileId ID of the view (profile) to be updated.
   * @param Google_Profile $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Profile
   */
  public function update($accountId, $webPropertyId, $profileId, Google_Service_Analytics_Profile $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_Profile");
  }
}
/**
 * The "segments" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $segments = $analyticsService->segments;
 *  </code>
 */
class Google_Service_Analytics_ManagementSegments_Resource extends Google_Service_Resource
{

  /**
   * Lists segments to which the user has access.
   * (segments.listManagementSegments)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of segments to include in this
   * response.
   * @opt_param int start-index An index of the first segment to retrieve. Use
   * this parameter as a pagination mechanism along with the max-results
   * parameter.
   * @return Google_Service_Analytics_Segments
   */
  public function listManagementSegments($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Segments");
  }
}
/**
 * The "unsampledReports" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $unsampledReports = $analyticsService->unsampledReports;
 *  </code>
 */
class Google_Service_Analytics_ManagementUnsampledReports_Resource extends Google_Service_Resource
{

  /**
   * Returns a single unsampled report. (unsampledReports.get)
   *
   * @param string $accountId Account ID to retrieve unsampled report for.
   * @param string $webPropertyId Web property ID to retrieve unsampled reports
   * for.
   * @param string $profileId View (Profile) ID to retrieve unsampled report for.
   * @param string $unsampledReportId ID of the unsampled report to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_UnsampledReport
   */
  public function get($accountId, $webPropertyId, $profileId, $unsampledReportId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'unsampledReportId' => $unsampledReportId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_UnsampledReport");
  }

  /**
   * Create a new unsampled report. (unsampledReports.insert)
   *
   * @param string $accountId Account ID to create the unsampled report for.
   * @param string $webPropertyId Web property ID to create the unsampled report
   * for.
   * @param string $profileId View (Profile) ID to create the unsampled report
   * for.
   * @param Google_UnsampledReport $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_UnsampledReport
   */
  public function insert($accountId, $webPropertyId, $profileId, Google_Service_Analytics_UnsampledReport $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_UnsampledReport");
  }

  /**
   * Lists unsampled reports to which the user has access.
   * (unsampledReports.listManagementUnsampledReports)
   *
   * @param string $accountId Account ID to retrieve unsampled reports for. Must
   * be a specific account ID, ~all is not supported.
   * @param string $webPropertyId Web property ID to retrieve unsampled reports
   * for. Must be a specific web property ID, ~all is not supported.
   * @param string $profileId View (Profile) ID to retrieve unsampled reports for.
   * Must be a specific view (profile) ID, ~all is not supported.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of unsampled reports to include
   * in this response.
   * @opt_param int start-index An index of the first unsampled report to
   * retrieve. Use this parameter as a pagination mechanism along with the max-
   * results parameter.
   * @return Google_Service_Analytics_UnsampledReports
   */
  public function listManagementUnsampledReports($accountId, $webPropertyId, $profileId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'profileId' => $profileId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_UnsampledReports");
  }
}
/**
 * The "uploads" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $uploads = $analyticsService->uploads;
 *  </code>
 */
class Google_Service_Analytics_ManagementUploads_Resource extends Google_Service_Resource
{

  /**
   * Delete data associated with a previous upload. (uploads.deleteUploadData)
   *
   * @param string $accountId Account Id for the uploads to be deleted.
   * @param string $webPropertyId Web property Id for the uploads to be deleted.
   * @param string $customDataSourceId Custom data source Id for the uploads to be
   * deleted.
   * @param Google_AnalyticsDataimportDeleteUploadDataRequest $postBody
   * @param array $optParams Optional parameters.
   */
  public function deleteUploadData($accountId, $webPropertyId, $customDataSourceId, Google_Service_Analytics_AnalyticsDataimportDeleteUploadDataRequest $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDataSourceId' => $customDataSourceId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('deleteUploadData', array($params));
  }

  /**
   * List uploads to which the user has access. (uploads.get)
   *
   * @param string $accountId Account Id for the upload to retrieve.
   * @param string $webPropertyId Web property Id for the upload to retrieve.
   * @param string $customDataSourceId Custom data source Id for upload to
   * retrieve.
   * @param string $uploadId Upload Id to retrieve.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Upload
   */
  public function get($accountId, $webPropertyId, $customDataSourceId, $uploadId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDataSourceId' => $customDataSourceId, 'uploadId' => $uploadId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_Upload");
  }

  /**
   * List uploads to which the user has access. (uploads.listManagementUploads)
   *
   * @param string $accountId Account Id for the uploads to retrieve.
   * @param string $webPropertyId Web property Id for the uploads to retrieve.
   * @param string $customDataSourceId Custom data source Id for uploads to
   * retrieve.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of uploads to include in this
   * response.
   * @opt_param int start-index A 1-based index of the first upload to retrieve.
   * Use this parameter as a pagination mechanism along with the max-results
   * parameter.
   * @return Google_Service_Analytics_Uploads
   */
  public function listManagementUploads($accountId, $webPropertyId, $customDataSourceId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDataSourceId' => $customDataSourceId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Uploads");
  }

  /**
   * Upload data for a custom data source. (uploads.uploadData)
   *
   * @param string $accountId Account Id associated with the upload.
   * @param string $webPropertyId Web property UA-string associated with the
   * upload.
   * @param string $customDataSourceId Custom data source Id to which the data
   * being uploaded belongs.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Upload
   */
  public function uploadData($accountId, $webPropertyId, $customDataSourceId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'customDataSourceId' => $customDataSourceId);
    $params = array_merge($params, $optParams);
    return $this->call('uploadData', array($params), "Google_Service_Analytics_Upload");
  }
}
/**
 * The "webPropertyAdWordsLinks" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $webPropertyAdWordsLinks = $analyticsService->webPropertyAdWordsLinks;
 *  </code>
 */
class Google_Service_Analytics_ManagementWebPropertyAdWordsLinks_Resource extends Google_Service_Resource
{

  /**
   * Deletes a web property-AdWords link. (webPropertyAdWordsLinks.delete)
   *
   * @param string $accountId ID of the account which the given web property
   * belongs to.
   * @param string $webPropertyId Web property ID to delete the AdWords link for.
   * @param string $webPropertyAdWordsLinkId Web property AdWords link ID.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $webPropertyId, $webPropertyAdWordsLinkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'webPropertyAdWordsLinkId' => $webPropertyAdWordsLinkId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Returns a web property-AdWords link to which the user has access.
   * (webPropertyAdWordsLinks.get)
   *
   * @param string $accountId ID of the account which the given web property
   * belongs to.
   * @param string $webPropertyId Web property ID to retrieve the AdWords link
   * for.
   * @param string $webPropertyAdWordsLinkId Web property-AdWords link ID.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityAdWordsLink
   */
  public function get($accountId, $webPropertyId, $webPropertyAdWordsLinkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'webPropertyAdWordsLinkId' => $webPropertyAdWordsLinkId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_EntityAdWordsLink");
  }

  /**
   * Creates a webProperty-AdWords link. (webPropertyAdWordsLinks.insert)
   *
   * @param string $accountId ID of the Google Analytics account to create the
   * link for.
   * @param string $webPropertyId Web property ID to create the link for.
   * @param Google_EntityAdWordsLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityAdWordsLink
   */
  public function insert($accountId, $webPropertyId, Google_Service_Analytics_EntityAdWordsLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_EntityAdWordsLink");
  }

  /**
   * Lists webProperty-AdWords links for a given web property.
   * (webPropertyAdWordsLinks.listManagementWebPropertyAdWordsLinks)
   *
   * @param string $accountId ID of the account which the given web property
   * belongs to.
   * @param string $webPropertyId Web property ID to retrieve the AdWords links
   * for.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of webProperty-AdWords links to
   * include in this response.
   * @opt_param int start-index An index of the first webProperty-AdWords link to
   * retrieve. Use this parameter as a pagination mechanism along with the max-
   * results parameter.
   * @return Google_Service_Analytics_EntityAdWordsLinks
   */
  public function listManagementWebPropertyAdWordsLinks($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_EntityAdWordsLinks");
  }

  /**
   * Updates an existing webProperty-AdWords link. This method supports patch
   * semantics. (webPropertyAdWordsLinks.patch)
   *
   * @param string $accountId ID of the account which the given web property
   * belongs to.
   * @param string $webPropertyId Web property ID to retrieve the AdWords link
   * for.
   * @param string $webPropertyAdWordsLinkId Web property-AdWords link ID.
   * @param Google_EntityAdWordsLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityAdWordsLink
   */
  public function patch($accountId, $webPropertyId, $webPropertyAdWordsLinkId, Google_Service_Analytics_EntityAdWordsLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'webPropertyAdWordsLinkId' => $webPropertyAdWordsLinkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_EntityAdWordsLink");
  }

  /**
   * Updates an existing webProperty-AdWords link.
   * (webPropertyAdWordsLinks.update)
   *
   * @param string $accountId ID of the account which the given web property
   * belongs to.
   * @param string $webPropertyId Web property ID to retrieve the AdWords link
   * for.
   * @param string $webPropertyAdWordsLinkId Web property-AdWords link ID.
   * @param Google_EntityAdWordsLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityAdWordsLink
   */
  public function update($accountId, $webPropertyId, $webPropertyAdWordsLinkId, Google_Service_Analytics_EntityAdWordsLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'webPropertyAdWordsLinkId' => $webPropertyAdWordsLinkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_EntityAdWordsLink");
  }
}
/**
 * The "webproperties" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $webproperties = $analyticsService->webproperties;
 *  </code>
 */
class Google_Service_Analytics_ManagementWebproperties_Resource extends Google_Service_Resource
{

  /**
   * Gets a web property to which the user has access. (webproperties.get)
   *
   * @param string $accountId Account ID to retrieve the web property for.
   * @param string $webPropertyId ID to retrieve the web property for.
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Webproperty
   */
  public function get($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Analytics_Webproperty");
  }

  /**
   * Create a new property if the account has fewer than 20 properties. Web
   * properties are visible in the Google Analytics interface only if they have at
   * least one profile. (webproperties.insert)
   *
   * @param string $accountId Account ID to create the web property for.
   * @param Google_Webproperty $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Webproperty
   */
  public function insert($accountId, Google_Service_Analytics_Webproperty $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_Webproperty");
  }

  /**
   * Lists web properties to which the user has access.
   * (webproperties.listManagementWebproperties)
   *
   * @param string $accountId Account ID to retrieve web properties for. Can
   * either be a specific account ID or '~all', which refers to all the accounts
   * that user has access to.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of web properties to include in
   * this response.
   * @opt_param int start-index An index of the first entity to retrieve. Use this
   * parameter as a pagination mechanism along with the max-results parameter.
   * @return Google_Service_Analytics_Webproperties
   */
  public function listManagementWebproperties($accountId, $optParams = array())
  {
    $params = array('accountId' => $accountId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Webproperties");
  }

  /**
   * Updates an existing web property. This method supports patch semantics.
   * (webproperties.patch)
   *
   * @param string $accountId Account ID to which the web property belongs
   * @param string $webPropertyId Web property ID
   * @param Google_Webproperty $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Webproperty
   */
  public function patch($accountId, $webPropertyId, Google_Service_Analytics_Webproperty $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('patch', array($params), "Google_Service_Analytics_Webproperty");
  }

  /**
   * Updates an existing web property. (webproperties.update)
   *
   * @param string $accountId Account ID to which the web property belongs
   * @param string $webPropertyId Web property ID
   * @param Google_Webproperty $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Webproperty
   */
  public function update($accountId, $webPropertyId, Google_Service_Analytics_Webproperty $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_Webproperty");
  }
}
/**
 * The "webpropertyUserLinks" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $webpropertyUserLinks = $analyticsService->webpropertyUserLinks;
 *  </code>
 */
class Google_Service_Analytics_ManagementWebpropertyUserLinks_Resource extends Google_Service_Resource
{

  /**
   * Removes a user from the given web property. (webpropertyUserLinks.delete)
   *
   * @param string $accountId Account ID to delete the user link for.
   * @param string $webPropertyId Web Property ID to delete the user link for.
   * @param string $linkId Link ID to delete the user link for.
   * @param array $optParams Optional parameters.
   */
  public function delete($accountId, $webPropertyId, $linkId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'linkId' => $linkId);
    $params = array_merge($params, $optParams);
    return $this->call('delete', array($params));
  }

  /**
   * Adds a new user to the given web property. (webpropertyUserLinks.insert)
   *
   * @param string $accountId Account ID to create the user link for.
   * @param string $webPropertyId Web Property ID to create the user link for.
   * @param Google_EntityUserLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityUserLink
   */
  public function insert($accountId, $webPropertyId, Google_Service_Analytics_EntityUserLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('insert', array($params), "Google_Service_Analytics_EntityUserLink");
  }

  /**
   * Lists webProperty-user links for a given web property.
   * (webpropertyUserLinks.listManagementWebpropertyUserLinks)
   *
   * @param string $accountId Account ID which the given web property belongs to.
   * @param string $webPropertyId Web Property ID for the webProperty-user links
   * to retrieve. Can either be a specific web property ID or '~all', which refers
   * to all the web properties that user has access to.
   * @param array $optParams Optional parameters.
   *
   * @opt_param int max-results The maximum number of webProperty-user Links to
   * include in this response.
   * @opt_param int start-index An index of the first webProperty-user link to
   * retrieve. Use this parameter as a pagination mechanism along with the max-
   * results parameter.
   * @return Google_Service_Analytics_EntityUserLinks
   */
  public function listManagementWebpropertyUserLinks($accountId, $webPropertyId, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_EntityUserLinks");
  }

  /**
   * Updates permissions for an existing user on the given web property.
   * (webpropertyUserLinks.update)
   *
   * @param string $accountId Account ID to update the account-user link for.
   * @param string $webPropertyId Web property ID to update the account-user link
   * for.
   * @param string $linkId Link ID to update the account-user link for.
   * @param Google_EntityUserLink $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_EntityUserLink
   */
  public function update($accountId, $webPropertyId, $linkId, Google_Service_Analytics_EntityUserLink $postBody, $optParams = array())
  {
    $params = array('accountId' => $accountId, 'webPropertyId' => $webPropertyId, 'linkId' => $linkId, 'postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('update', array($params), "Google_Service_Analytics_EntityUserLink");
  }
}

/**
 * The "metadata" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $metadata = $analyticsService->metadata;
 *  </code>
 */
class Google_Service_Analytics_Metadata_Resource extends Google_Service_Resource
{
}

/**
 * The "columns" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $columns = $analyticsService->columns;
 *  </code>
 */
class Google_Service_Analytics_MetadataColumns_Resource extends Google_Service_Resource
{

  /**
   * Lists all columns for a report type (columns.listMetadataColumns)
   *
   * @param string $reportType Report type. Allowed Values: 'ga'. Where 'ga'
   * corresponds to the Core Reporting API
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_Columns
   */
  public function listMetadataColumns($reportType, $optParams = array())
  {
    $params = array('reportType' => $reportType);
    $params = array_merge($params, $optParams);
    return $this->call('list', array($params), "Google_Service_Analytics_Columns");
  }
}

/**
 * The "provisioning" collection of methods.
 * Typical usage is:
 *  <code>
 *   $analyticsService = new Google_Service_Analytics(...);
 *   $provisioning = $analyticsService->provisioning;
 *  </code>
 */
class Google_Service_Analytics_Provisioning_Resource extends Google_Service_Resource
{

  /**
   * Creates an account ticket. (provisioning.createAccountTicket)
   *
   * @param Google_AccountTicket $postBody
   * @param array $optParams Optional parameters.
   * @return Google_Service_Analytics_AccountTicket
   */
  public function createAccountTicket(Google_Service_Analytics_AccountTicket $postBody, $optParams = array())
  {
    $params = array('postBody' => $postBody);
    $params = array_merge($params, $optParams);
    return $this->call('createAccountTicket', array($params), "Google_Service_Analytics_AccountTicket");
  }
}




class Google_Service_Analytics_Account extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $childLinkType = 'Google_Service_Analytics_AccountChildLink';
  protected $childLinkDataType = '';
  public $created;
  public $id;
  public $kind;
  public $name;
  protected $permissionsType = 'Google_Service_Analytics_AccountPermissions';
  protected $permissionsDataType = '';
  public $selfLink;
  public $updated;


  public function setChildLink(Google_Service_Analytics_AccountChildLink $childLink)
  {
    $this->childLink = $childLink;
  }
  public function getChildLink()
  {
    return $this->childLink;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setPermissions(Google_Service_Analytics_AccountPermissions $permissions)
  {
    $this->permissions = $permissions;
  }
  public function getPermissions()
  {
    return $this->permissions;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
}

class Google_Service_Analytics_AccountChildLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_AccountPermissions extends Google_Collection
{
  protected $collection_key = 'effective';
  protected $internal_gapi_mappings = array(
  );
  public $effective;


  public function setEffective($effective)
  {
    $this->effective = $effective;
  }
  public function getEffective()
  {
    return $this->effective;
  }
}

class Google_Service_Analytics_AccountRef extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $id;
  public $kind;
  public $name;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_Analytics_AccountSummaries extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_AccountSummary';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_AccountSummary extends Google_Collection
{
  protected $collection_key = 'webProperties';
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $kind;
  public $name;
  protected $webPropertiesType = 'Google_Service_Analytics_WebPropertySummary';
  protected $webPropertiesDataType = 'array';


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setWebProperties($webProperties)
  {
    $this->webProperties = $webProperties;
  }
  public function getWebProperties()
  {
    return $this->webProperties;
  }
}

class Google_Service_Analytics_AccountTicket extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $accountType = 'Google_Service_Analytics_Account';
  protected $accountDataType = '';
  public $id;
  public $kind;
  protected $profileType = 'Google_Service_Analytics_Profile';
  protected $profileDataType = '';
  public $redirectUri;
  protected $webpropertyType = 'Google_Service_Analytics_Webproperty';
  protected $webpropertyDataType = '';


  public function setAccount(Google_Service_Analytics_Account $account)
  {
    $this->account = $account;
  }
  public function getAccount()
  {
    return $this->account;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setProfile(Google_Service_Analytics_Profile $profile)
  {
    $this->profile = $profile;
  }
  public function getProfile()
  {
    return $this->profile;
  }
  public function setRedirectUri($redirectUri)
  {
    $this->redirectUri = $redirectUri;
  }
  public function getRedirectUri()
  {
    return $this->redirectUri;
  }
  public function setWebproperty(Google_Service_Analytics_Webproperty $webproperty)
  {
    $this->webproperty = $webproperty;
  }
  public function getWebproperty()
  {
    return $this->webproperty;
  }
}

class Google_Service_Analytics_Accounts extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Account';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_AdWordsAccount extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $autoTaggingEnabled;
  public $customerId;
  public $kind;


  public function setAutoTaggingEnabled($autoTaggingEnabled)
  {
    $this->autoTaggingEnabled = $autoTaggingEnabled;
  }
  public function getAutoTaggingEnabled()
  {
    return $this->autoTaggingEnabled;
  }
  public function setCustomerId($customerId)
  {
    $this->customerId = $customerId;
  }
  public function getCustomerId()
  {
    return $this->customerId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_Analytics_AnalyticsDataimportDeleteUploadDataRequest extends Google_Collection
{
  protected $collection_key = 'customDataImportUids';
  protected $internal_gapi_mappings = array(
  );
  public $customDataImportUids;


  public function setCustomDataImportUids($customDataImportUids)
  {
    $this->customDataImportUids = $customDataImportUids;
  }
  public function getCustomDataImportUids()
  {
    return $this->customDataImportUids;
  }
}

class Google_Service_Analytics_Column extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $attributes;
  public $id;
  public $kind;


  public function setAttributes($attributes)
  {
    $this->attributes = $attributes;
  }
  public function getAttributes()
  {
    return $this->attributes;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_Analytics_ColumnAttributes extends Google_Model
{
}

class Google_Service_Analytics_Columns extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  public $attributeNames;
  public $etag;
  protected $itemsType = 'Google_Service_Analytics_Column';
  protected $itemsDataType = 'array';
  public $kind;
  public $totalResults;


  public function setAttributeNames($attributeNames)
  {
    $this->attributeNames = $attributeNames;
  }
  public function getAttributeNames()
  {
    return $this->attributeNames;
  }
  public function setEtag($etag)
  {
    $this->etag = $etag;
  }
  public function getEtag()
  {
    return $this->etag;
  }
  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
}

class Google_Service_Analytics_CustomDataSource extends Google_Collection
{
  protected $collection_key = 'profilesLinked';
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  protected $childLinkType = 'Google_Service_Analytics_CustomDataSourceChildLink';
  protected $childLinkDataType = '';
  public $created;
  public $description;
  public $id;
  public $importBehavior;
  public $kind;
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_CustomDataSourceParentLink';
  protected $parentLinkDataType = '';
  public $profilesLinked;
  public $selfLink;
  public $type;
  public $updated;
  public $uploadType;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setChildLink(Google_Service_Analytics_CustomDataSourceChildLink $childLink)
  {
    $this->childLink = $childLink;
  }
  public function getChildLink()
  {
    return $this->childLink;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setDescription($description)
  {
    $this->description = $description;
  }
  public function getDescription()
  {
    return $this->description;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setImportBehavior($importBehavior)
  {
    $this->importBehavior = $importBehavior;
  }
  public function getImportBehavior()
  {
    return $this->importBehavior;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_CustomDataSourceParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setProfilesLinked($profilesLinked)
  {
    $this->profilesLinked = $profilesLinked;
  }
  public function getProfilesLinked()
  {
    return $this->profilesLinked;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setUploadType($uploadType)
  {
    $this->uploadType = $uploadType;
  }
  public function getUploadType()
  {
    return $this->uploadType;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_CustomDataSourceChildLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_CustomDataSourceParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_CustomDataSources extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_CustomDataSource';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_CustomDimension extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $active;
  public $created;
  public $id;
  public $index;
  public $kind;
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_CustomDimensionParentLink';
  protected $parentLinkDataType = '';
  public $scope;
  public $selfLink;
  public $updated;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setActive($active)
  {
    $this->active = $active;
  }
  public function getActive()
  {
    return $this->active;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setIndex($index)
  {
    $this->index = $index;
  }
  public function getIndex()
  {
    return $this->index;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_CustomDimensionParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setScope($scope)
  {
    $this->scope = $scope;
  }
  public function getScope()
  {
    return $this->scope;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_CustomDimensionParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_CustomDimensions extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_CustomDimension';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_CustomMetric extends Google_Model
{
  protected $internal_gapi_mappings = array(
        "maxValue" => "max_value",
        "minValue" => "min_value",
  );
  public $accountId;
  public $active;
  public $created;
  public $id;
  public $index;
  public $kind;
  public $maxValue;
  public $minValue;
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_CustomMetricParentLink';
  protected $parentLinkDataType = '';
  public $scope;
  public $selfLink;
  public $type;
  public $updated;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setActive($active)
  {
    $this->active = $active;
  }
  public function getActive()
  {
    return $this->active;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setIndex($index)
  {
    $this->index = $index;
  }
  public function getIndex()
  {
    return $this->index;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setMaxValue($maxValue)
  {
    $this->maxValue = $maxValue;
  }
  public function getMaxValue()
  {
    return $this->maxValue;
  }
  public function setMinValue($minValue)
  {
    $this->minValue = $minValue;
  }
  public function getMinValue()
  {
    return $this->minValue;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_CustomMetricParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setScope($scope)
  {
    $this->scope = $scope;
  }
  public function getScope()
  {
    return $this->scope;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_CustomMetricParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_CustomMetrics extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_CustomMetric';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_EntityAdWordsLink extends Google_Collection
{
  protected $collection_key = 'profileIds';
  protected $internal_gapi_mappings = array(
  );
  protected $adWordsAccountsType = 'Google_Service_Analytics_AdWordsAccount';
  protected $adWordsAccountsDataType = 'array';
  protected $entityType = 'Google_Service_Analytics_EntityAdWordsLinkEntity';
  protected $entityDataType = '';
  public $id;
  public $kind;
  public $name;
  public $profileIds;
  public $selfLink;


  public function setAdWordsAccounts($adWordsAccounts)
  {
    $this->adWordsAccounts = $adWordsAccounts;
  }
  public function getAdWordsAccounts()
  {
    return $this->adWordsAccounts;
  }
  public function setEntity(Google_Service_Analytics_EntityAdWordsLinkEntity $entity)
  {
    $this->entity = $entity;
  }
  public function getEntity()
  {
    return $this->entity;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setProfileIds($profileIds)
  {
    $this->profileIds = $profileIds;
  }
  public function getProfileIds()
  {
    return $this->profileIds;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
}

class Google_Service_Analytics_EntityAdWordsLinkEntity extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $webPropertyRefType = 'Google_Service_Analytics_WebPropertyRef';
  protected $webPropertyRefDataType = '';


  public function setWebPropertyRef(Google_Service_Analytics_WebPropertyRef $webPropertyRef)
  {
    $this->webPropertyRef = $webPropertyRef;
  }
  public function getWebPropertyRef()
  {
    return $this->webPropertyRef;
  }
}

class Google_Service_Analytics_EntityAdWordsLinks extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_EntityAdWordsLink';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
}

class Google_Service_Analytics_EntityUserLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $entityType = 'Google_Service_Analytics_EntityUserLinkEntity';
  protected $entityDataType = '';
  public $id;
  public $kind;
  protected $permissionsType = 'Google_Service_Analytics_EntityUserLinkPermissions';
  protected $permissionsDataType = '';
  public $selfLink;
  protected $userRefType = 'Google_Service_Analytics_UserRef';
  protected $userRefDataType = '';


  public function setEntity(Google_Service_Analytics_EntityUserLinkEntity $entity)
  {
    $this->entity = $entity;
  }
  public function getEntity()
  {
    return $this->entity;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setPermissions(Google_Service_Analytics_EntityUserLinkPermissions $permissions)
  {
    $this->permissions = $permissions;
  }
  public function getPermissions()
  {
    return $this->permissions;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setUserRef(Google_Service_Analytics_UserRef $userRef)
  {
    $this->userRef = $userRef;
  }
  public function getUserRef()
  {
    return $this->userRef;
  }
}

class Google_Service_Analytics_EntityUserLinkEntity extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $accountRefType = 'Google_Service_Analytics_AccountRef';
  protected $accountRefDataType = '';
  protected $profileRefType = 'Google_Service_Analytics_ProfileRef';
  protected $profileRefDataType = '';
  protected $webPropertyRefType = 'Google_Service_Analytics_WebPropertyRef';
  protected $webPropertyRefDataType = '';


  public function setAccountRef(Google_Service_Analytics_AccountRef $accountRef)
  {
    $this->accountRef = $accountRef;
  }
  public function getAccountRef()
  {
    return $this->accountRef;
  }
  public function setProfileRef(Google_Service_Analytics_ProfileRef $profileRef)
  {
    $this->profileRef = $profileRef;
  }
  public function getProfileRef()
  {
    return $this->profileRef;
  }
  public function setWebPropertyRef(Google_Service_Analytics_WebPropertyRef $webPropertyRef)
  {
    $this->webPropertyRef = $webPropertyRef;
  }
  public function getWebPropertyRef()
  {
    return $this->webPropertyRef;
  }
}

class Google_Service_Analytics_EntityUserLinkPermissions extends Google_Collection
{
  protected $collection_key = 'local';
  protected $internal_gapi_mappings = array(
  );
  public $effective;
  public $local;


  public function setEffective($effective)
  {
    $this->effective = $effective;
  }
  public function getEffective()
  {
    return $this->effective;
  }
  public function setLocal($local)
  {
    $this->local = $local;
  }
  public function getLocal()
  {
    return $this->local;
  }
}

class Google_Service_Analytics_EntityUserLinks extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_EntityUserLink';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
}

class Google_Service_Analytics_Experiment extends Google_Collection
{
  protected $collection_key = 'variations';
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $created;
  public $description;
  public $editableInGaUi;
  public $endTime;
  public $equalWeighting;
  public $id;
  public $internalWebPropertyId;
  public $kind;
  public $minimumExperimentLengthInDays;
  public $name;
  public $objectiveMetric;
  public $optimizationType;
  protected $parentLinkType = 'Google_Service_Analytics_ExperimentParentLink';
  protected $parentLinkDataType = '';
  public $profileId;
  public $reasonExperimentEnded;
  public $rewriteVariationUrlsAsOriginal;
  public $selfLink;
  public $servingFramework;
  public $snippet;
  public $startTime;
  public $status;
  public $trafficCoverage;
  public $updated;
  protected $variationsType = 'Google_Service_Analytics_ExperimentVariations';
  protected $variationsDataType = 'array';
  public $webPropertyId;
  public $winnerConfidenceLevel;
  public $winnerFound;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setDescription($description)
  {
    $this->description = $description;
  }
  public function getDescription()
  {
    return $this->description;
  }
  public function setEditableInGaUi($editableInGaUi)
  {
    $this->editableInGaUi = $editableInGaUi;
  }
  public function getEditableInGaUi()
  {
    return $this->editableInGaUi;
  }
  public function setEndTime($endTime)
  {
    $this->endTime = $endTime;
  }
  public function getEndTime()
  {
    return $this->endTime;
  }
  public function setEqualWeighting($equalWeighting)
  {
    $this->equalWeighting = $equalWeighting;
  }
  public function getEqualWeighting()
  {
    return $this->equalWeighting;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setMinimumExperimentLengthInDays($minimumExperimentLengthInDays)
  {
    $this->minimumExperimentLengthInDays = $minimumExperimentLengthInDays;
  }
  public function getMinimumExperimentLengthInDays()
  {
    return $this->minimumExperimentLengthInDays;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setObjectiveMetric($objectiveMetric)
  {
    $this->objectiveMetric = $objectiveMetric;
  }
  public function getObjectiveMetric()
  {
    return $this->objectiveMetric;
  }
  public function setOptimizationType($optimizationType)
  {
    $this->optimizationType = $optimizationType;
  }
  public function getOptimizationType()
  {
    return $this->optimizationType;
  }
  public function setParentLink(Google_Service_Analytics_ExperimentParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setProfileId($profileId)
  {
    $this->profileId = $profileId;
  }
  public function getProfileId()
  {
    return $this->profileId;
  }
  public function setReasonExperimentEnded($reasonExperimentEnded)
  {
    $this->reasonExperimentEnded = $reasonExperimentEnded;
  }
  public function getReasonExperimentEnded()
  {
    return $this->reasonExperimentEnded;
  }
  public function setRewriteVariationUrlsAsOriginal($rewriteVariationUrlsAsOriginal)
  {
    $this->rewriteVariationUrlsAsOriginal = $rewriteVariationUrlsAsOriginal;
  }
  public function getRewriteVariationUrlsAsOriginal()
  {
    return $this->rewriteVariationUrlsAsOriginal;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setServingFramework($servingFramework)
  {
    $this->servingFramework = $servingFramework;
  }
  public function getServingFramework()
  {
    return $this->servingFramework;
  }
  public function setSnippet($snippet)
  {
    $this->snippet = $snippet;
  }
  public function getSnippet()
  {
    return $this->snippet;
  }
  public function setStartTime($startTime)
  {
    $this->startTime = $startTime;
  }
  public function getStartTime()
  {
    return $this->startTime;
  }
  public function setStatus($status)
  {
    $this->status = $status;
  }
  public function getStatus()
  {
    return $this->status;
  }
  public function setTrafficCoverage($trafficCoverage)
  {
    $this->trafficCoverage = $trafficCoverage;
  }
  public function getTrafficCoverage()
  {
    return $this->trafficCoverage;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setVariations($variations)
  {
    $this->variations = $variations;
  }
  public function getVariations()
  {
    return $this->variations;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
  public function setWinnerConfidenceLevel($winnerConfidenceLevel)
  {
    $this->winnerConfidenceLevel = $winnerConfidenceLevel;
  }
  public function getWinnerConfidenceLevel()
  {
    return $this->winnerConfidenceLevel;
  }
  public function setWinnerFound($winnerFound)
  {
    $this->winnerFound = $winnerFound;
  }
  public function getWinnerFound()
  {
    return $this->winnerFound;
  }
}

class Google_Service_Analytics_ExperimentParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_ExperimentVariations extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $name;
  public $status;
  public $url;
  public $weight;
  public $won;


  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setStatus($status)
  {
    $this->status = $status;
  }
  public function getStatus()
  {
    return $this->status;
  }
  public function setUrl($url)
  {
    $this->url = $url;
  }
  public function getUrl()
  {
    return $this->url;
  }
  public function setWeight($weight)
  {
    $this->weight = $weight;
  }
  public function getWeight()
  {
    return $this->weight;
  }
  public function setWon($won)
  {
    $this->won = $won;
  }
  public function getWon()
  {
    return $this->won;
  }
}

class Google_Service_Analytics_Experiments extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Experiment';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_Filter extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  protected $advancedDetailsType = 'Google_Service_Analytics_FilterAdvancedDetails';
  protected $advancedDetailsDataType = '';
  public $created;
  protected $excludeDetailsType = 'Google_Service_Analytics_FilterExpression';
  protected $excludeDetailsDataType = '';
  public $id;
  protected $includeDetailsType = 'Google_Service_Analytics_FilterExpression';
  protected $includeDetailsDataType = '';
  public $kind;
  protected $lowercaseDetailsType = 'Google_Service_Analytics_FilterLowercaseDetails';
  protected $lowercaseDetailsDataType = '';
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_FilterParentLink';
  protected $parentLinkDataType = '';
  protected $searchAndReplaceDetailsType = 'Google_Service_Analytics_FilterSearchAndReplaceDetails';
  protected $searchAndReplaceDetailsDataType = '';
  public $selfLink;
  public $type;
  public $updated;
  protected $uppercaseDetailsType = 'Google_Service_Analytics_FilterUppercaseDetails';
  protected $uppercaseDetailsDataType = '';


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setAdvancedDetails(Google_Service_Analytics_FilterAdvancedDetails $advancedDetails)
  {
    $this->advancedDetails = $advancedDetails;
  }
  public function getAdvancedDetails()
  {
    return $this->advancedDetails;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setExcludeDetails(Google_Service_Analytics_FilterExpression $excludeDetails)
  {
    $this->excludeDetails = $excludeDetails;
  }
  public function getExcludeDetails()
  {
    return $this->excludeDetails;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setIncludeDetails(Google_Service_Analytics_FilterExpression $includeDetails)
  {
    $this->includeDetails = $includeDetails;
  }
  public function getIncludeDetails()
  {
    return $this->includeDetails;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setLowercaseDetails(Google_Service_Analytics_FilterLowercaseDetails $lowercaseDetails)
  {
    $this->lowercaseDetails = $lowercaseDetails;
  }
  public function getLowercaseDetails()
  {
    return $this->lowercaseDetails;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_FilterParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setSearchAndReplaceDetails(Google_Service_Analytics_FilterSearchAndReplaceDetails $searchAndReplaceDetails)
  {
    $this->searchAndReplaceDetails = $searchAndReplaceDetails;
  }
  public function getSearchAndReplaceDetails()
  {
    return $this->searchAndReplaceDetails;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setUppercaseDetails(Google_Service_Analytics_FilterUppercaseDetails $uppercaseDetails)
  {
    $this->uppercaseDetails = $uppercaseDetails;
  }
  public function getUppercaseDetails()
  {
    return $this->uppercaseDetails;
  }
}

class Google_Service_Analytics_FilterAdvancedDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $caseSensitive;
  public $extractA;
  public $extractB;
  public $fieldA;
  public $fieldARequired;
  public $fieldB;
  public $fieldBRequired;
  public $outputConstructor;
  public $outputToField;
  public $overrideOutputField;


  public function setCaseSensitive($caseSensitive)
  {
    $this->caseSensitive = $caseSensitive;
  }
  public function getCaseSensitive()
  {
    return $this->caseSensitive;
  }
  public function setExtractA($extractA)
  {
    $this->extractA = $extractA;
  }
  public function getExtractA()
  {
    return $this->extractA;
  }
  public function setExtractB($extractB)
  {
    $this->extractB = $extractB;
  }
  public function getExtractB()
  {
    return $this->extractB;
  }
  public function setFieldA($fieldA)
  {
    $this->fieldA = $fieldA;
  }
  public function getFieldA()
  {
    return $this->fieldA;
  }
  public function setFieldARequired($fieldARequired)
  {
    $this->fieldARequired = $fieldARequired;
  }
  public function getFieldARequired()
  {
    return $this->fieldARequired;
  }
  public function setFieldB($fieldB)
  {
    $this->fieldB = $fieldB;
  }
  public function getFieldB()
  {
    return $this->fieldB;
  }
  public function setFieldBRequired($fieldBRequired)
  {
    $this->fieldBRequired = $fieldBRequired;
  }
  public function getFieldBRequired()
  {
    return $this->fieldBRequired;
  }
  public function setOutputConstructor($outputConstructor)
  {
    $this->outputConstructor = $outputConstructor;
  }
  public function getOutputConstructor()
  {
    return $this->outputConstructor;
  }
  public function setOutputToField($outputToField)
  {
    $this->outputToField = $outputToField;
  }
  public function getOutputToField()
  {
    return $this->outputToField;
  }
  public function setOverrideOutputField($overrideOutputField)
  {
    $this->overrideOutputField = $overrideOutputField;
  }
  public function getOverrideOutputField()
  {
    return $this->overrideOutputField;
  }
}

class Google_Service_Analytics_FilterExpression extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $caseSensitive;
  public $expressionValue;
  public $field;
  public $kind;
  public $matchType;


  public function setCaseSensitive($caseSensitive)
  {
    $this->caseSensitive = $caseSensitive;
  }
  public function getCaseSensitive()
  {
    return $this->caseSensitive;
  }
  public function setExpressionValue($expressionValue)
  {
    $this->expressionValue = $expressionValue;
  }
  public function getExpressionValue()
  {
    return $this->expressionValue;
  }
  public function setField($field)
  {
    $this->field = $field;
  }
  public function getField()
  {
    return $this->field;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setMatchType($matchType)
  {
    $this->matchType = $matchType;
  }
  public function getMatchType()
  {
    return $this->matchType;
  }
}

class Google_Service_Analytics_FilterLowercaseDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $field;


  public function setField($field)
  {
    $this->field = $field;
  }
  public function getField()
  {
    return $this->field;
  }
}

class Google_Service_Analytics_FilterParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_FilterRef extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $href;
  public $id;
  public $kind;
  public $name;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_Analytics_FilterSearchAndReplaceDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $caseSensitive;
  public $field;
  public $replaceString;
  public $searchString;


  public function setCaseSensitive($caseSensitive)
  {
    $this->caseSensitive = $caseSensitive;
  }
  public function getCaseSensitive()
  {
    return $this->caseSensitive;
  }
  public function setField($field)
  {
    $this->field = $field;
  }
  public function getField()
  {
    return $this->field;
  }
  public function setReplaceString($replaceString)
  {
    $this->replaceString = $replaceString;
  }
  public function getReplaceString()
  {
    return $this->replaceString;
  }
  public function setSearchString($searchString)
  {
    $this->searchString = $searchString;
  }
  public function getSearchString()
  {
    return $this->searchString;
  }
}

class Google_Service_Analytics_FilterUppercaseDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $field;


  public function setField($field)
  {
    $this->field = $field;
  }
  public function getField()
  {
    return $this->field;
  }
}

class Google_Service_Analytics_Filters extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Filter';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_GaData extends Google_Collection
{
  protected $collection_key = 'rows';
  protected $internal_gapi_mappings = array(
  );
  protected $columnHeadersType = 'Google_Service_Analytics_GaDataColumnHeaders';
  protected $columnHeadersDataType = 'array';
  public $containsSampledData;
  protected $dataTableType = 'Google_Service_Analytics_GaDataDataTable';
  protected $dataTableDataType = '';
  public $id;
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  protected $profileInfoType = 'Google_Service_Analytics_GaDataProfileInfo';
  protected $profileInfoDataType = '';
  protected $queryType = 'Google_Service_Analytics_GaDataQuery';
  protected $queryDataType = '';
  public $rows;
  public $sampleSize;
  public $sampleSpace;
  public $selfLink;
  public $totalResults;
  public $totalsForAllResults;


  public function setColumnHeaders($columnHeaders)
  {
    $this->columnHeaders = $columnHeaders;
  }
  public function getColumnHeaders()
  {
    return $this->columnHeaders;
  }
  public function setContainsSampledData($containsSampledData)
  {
    $this->containsSampledData = $containsSampledData;
  }
  public function getContainsSampledData()
  {
    return $this->containsSampledData;
  }
  public function setDataTable(Google_Service_Analytics_GaDataDataTable $dataTable)
  {
    $this->dataTable = $dataTable;
  }
  public function getDataTable()
  {
    return $this->dataTable;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setProfileInfo(Google_Service_Analytics_GaDataProfileInfo $profileInfo)
  {
    $this->profileInfo = $profileInfo;
  }
  public function getProfileInfo()
  {
    return $this->profileInfo;
  }
  public function setQuery(Google_Service_Analytics_GaDataQuery $query)
  {
    $this->query = $query;
  }
  public function getQuery()
  {
    return $this->query;
  }
  public function setRows($rows)
  {
    $this->rows = $rows;
  }
  public function getRows()
  {
    return $this->rows;
  }
  public function setSampleSize($sampleSize)
  {
    $this->sampleSize = $sampleSize;
  }
  public function getSampleSize()
  {
    return $this->sampleSize;
  }
  public function setSampleSpace($sampleSpace)
  {
    $this->sampleSpace = $sampleSpace;
  }
  public function getSampleSpace()
  {
    return $this->sampleSpace;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setTotalsForAllResults($totalsForAllResults)
  {
    $this->totalsForAllResults = $totalsForAllResults;
  }
  public function getTotalsForAllResults()
  {
    return $this->totalsForAllResults;
  }
}

class Google_Service_Analytics_GaDataColumnHeaders extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $columnType;
  public $dataType;
  public $name;


  public function setColumnType($columnType)
  {
    $this->columnType = $columnType;
  }
  public function getColumnType()
  {
    return $this->columnType;
  }
  public function setDataType($dataType)
  {
    $this->dataType = $dataType;
  }
  public function getDataType()
  {
    return $this->dataType;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_Analytics_GaDataDataTable extends Google_Collection
{
  protected $collection_key = 'rows';
  protected $internal_gapi_mappings = array(
  );
  protected $colsType = 'Google_Service_Analytics_GaDataDataTableCols';
  protected $colsDataType = 'array';
  protected $rowsType = 'Google_Service_Analytics_GaDataDataTableRows';
  protected $rowsDataType = 'array';


  public function setCols($cols)
  {
    $this->cols = $cols;
  }
  public function getCols()
  {
    return $this->cols;
  }
  public function setRows($rows)
  {
    $this->rows = $rows;
  }
  public function getRows()
  {
    return $this->rows;
  }
}

class Google_Service_Analytics_GaDataDataTableCols extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $label;
  public $type;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setLabel($label)
  {
    $this->label = $label;
  }
  public function getLabel()
  {
    return $this->label;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_GaDataDataTableRows extends Google_Collection
{
  protected $collection_key = 'c';
  protected $internal_gapi_mappings = array(
  );
  protected $cType = 'Google_Service_Analytics_GaDataDataTableRowsC';
  protected $cDataType = 'array';


  public function setC($c)
  {
    $this->c = $c;
  }
  public function getC()
  {
    return $this->c;
  }
}

class Google_Service_Analytics_GaDataDataTableRowsC extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $v;


  public function setV($v)
  {
    $this->v = $v;
  }
  public function getV()
  {
    return $this->v;
  }
}

class Google_Service_Analytics_GaDataProfileInfo extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $internalWebPropertyId;
  public $profileId;
  public $profileName;
  public $tableId;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setProfileId($profileId)
  {
    $this->profileId = $profileId;
  }
  public function getProfileId()
  {
    return $this->profileId;
  }
  public function setProfileName($profileName)
  {
    $this->profileName = $profileName;
  }
  public function getProfileName()
  {
    return $this->profileName;
  }
  public function setTableId($tableId)
  {
    $this->tableId = $tableId;
  }
  public function getTableId()
  {
    return $this->tableId;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_GaDataQuery extends Google_Collection
{
  protected $collection_key = 'sort';
  protected $internal_gapi_mappings = array(
        "endDate" => "end-date",
        "maxResults" => "max-results",
        "startDate" => "start-date",
        "startIndex" => "start-index",
  );
  public $dimensions;
  public $endDate;
  public $filters;
  public $ids;
  public $maxResults;
  public $metrics;
  public $samplingLevel;
  public $segment;
  public $sort;
  public $startDate;
  public $startIndex;


  public function setDimensions($dimensions)
  {
    $this->dimensions = $dimensions;
  }
  public function getDimensions()
  {
    return $this->dimensions;
  }
  public function setEndDate($endDate)
  {
    $this->endDate = $endDate;
  }
  public function getEndDate()
  {
    return $this->endDate;
  }
  public function setFilters($filters)
  {
    $this->filters = $filters;
  }
  public function getFilters()
  {
    return $this->filters;
  }
  public function setIds($ids)
  {
    $this->ids = $ids;
  }
  public function getIds()
  {
    return $this->ids;
  }
  public function setMaxResults($maxResults)
  {
    $this->maxResults = $maxResults;
  }
  public function getMaxResults()
  {
    return $this->maxResults;
  }
  public function setMetrics($metrics)
  {
    $this->metrics = $metrics;
  }
  public function getMetrics()
  {
    return $this->metrics;
  }
  public function setSamplingLevel($samplingLevel)
  {
    $this->samplingLevel = $samplingLevel;
  }
  public function getSamplingLevel()
  {
    return $this->samplingLevel;
  }
  public function setSegment($segment)
  {
    $this->segment = $segment;
  }
  public function getSegment()
  {
    return $this->segment;
  }
  public function setSort($sort)
  {
    $this->sort = $sort;
  }
  public function getSort()
  {
    return $this->sort;
  }
  public function setStartDate($startDate)
  {
    $this->startDate = $startDate;
  }
  public function getStartDate()
  {
    return $this->startDate;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
}

class Google_Service_Analytics_GaDataTotalsForAllResults extends Google_Model
{
}

class Google_Service_Analytics_Goal extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $active;
  public $created;
  protected $eventDetailsType = 'Google_Service_Analytics_GoalEventDetails';
  protected $eventDetailsDataType = '';
  public $id;
  public $internalWebPropertyId;
  public $kind;
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_GoalParentLink';
  protected $parentLinkDataType = '';
  public $profileId;
  public $selfLink;
  public $type;
  public $updated;
  protected $urlDestinationDetailsType = 'Google_Service_Analytics_GoalUrlDestinationDetails';
  protected $urlDestinationDetailsDataType = '';
  public $value;
  protected $visitNumPagesDetailsType = 'Google_Service_Analytics_GoalVisitNumPagesDetails';
  protected $visitNumPagesDetailsDataType = '';
  protected $visitTimeOnSiteDetailsType = 'Google_Service_Analytics_GoalVisitTimeOnSiteDetails';
  protected $visitTimeOnSiteDetailsDataType = '';
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setActive($active)
  {
    $this->active = $active;
  }
  public function getActive()
  {
    return $this->active;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setEventDetails(Google_Service_Analytics_GoalEventDetails $eventDetails)
  {
    $this->eventDetails = $eventDetails;
  }
  public function getEventDetails()
  {
    return $this->eventDetails;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_GoalParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setProfileId($profileId)
  {
    $this->profileId = $profileId;
  }
  public function getProfileId()
  {
    return $this->profileId;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setUrlDestinationDetails(Google_Service_Analytics_GoalUrlDestinationDetails $urlDestinationDetails)
  {
    $this->urlDestinationDetails = $urlDestinationDetails;
  }
  public function getUrlDestinationDetails()
  {
    return $this->urlDestinationDetails;
  }
  public function setValue($value)
  {
    $this->value = $value;
  }
  public function getValue()
  {
    return $this->value;
  }
  public function setVisitNumPagesDetails(Google_Service_Analytics_GoalVisitNumPagesDetails $visitNumPagesDetails)
  {
    $this->visitNumPagesDetails = $visitNumPagesDetails;
  }
  public function getVisitNumPagesDetails()
  {
    return $this->visitNumPagesDetails;
  }
  public function setVisitTimeOnSiteDetails(Google_Service_Analytics_GoalVisitTimeOnSiteDetails $visitTimeOnSiteDetails)
  {
    $this->visitTimeOnSiteDetails = $visitTimeOnSiteDetails;
  }
  public function getVisitTimeOnSiteDetails()
  {
    return $this->visitTimeOnSiteDetails;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_GoalEventDetails extends Google_Collection
{
  protected $collection_key = 'eventConditions';
  protected $internal_gapi_mappings = array(
  );
  protected $eventConditionsType = 'Google_Service_Analytics_GoalEventDetailsEventConditions';
  protected $eventConditionsDataType = 'array';
  public $useEventValue;


  public function setEventConditions($eventConditions)
  {
    $this->eventConditions = $eventConditions;
  }
  public function getEventConditions()
  {
    return $this->eventConditions;
  }
  public function setUseEventValue($useEventValue)
  {
    $this->useEventValue = $useEventValue;
  }
  public function getUseEventValue()
  {
    return $this->useEventValue;
  }
}

class Google_Service_Analytics_GoalEventDetailsEventConditions extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $comparisonType;
  public $comparisonValue;
  public $expression;
  public $matchType;
  public $type;


  public function setComparisonType($comparisonType)
  {
    $this->comparisonType = $comparisonType;
  }
  public function getComparisonType()
  {
    return $this->comparisonType;
  }
  public function setComparisonValue($comparisonValue)
  {
    $this->comparisonValue = $comparisonValue;
  }
  public function getComparisonValue()
  {
    return $this->comparisonValue;
  }
  public function setExpression($expression)
  {
    $this->expression = $expression;
  }
  public function getExpression()
  {
    return $this->expression;
  }
  public function setMatchType($matchType)
  {
    $this->matchType = $matchType;
  }
  public function getMatchType()
  {
    return $this->matchType;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_GoalParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_GoalUrlDestinationDetails extends Google_Collection
{
  protected $collection_key = 'steps';
  protected $internal_gapi_mappings = array(
  );
  public $caseSensitive;
  public $firstStepRequired;
  public $matchType;
  protected $stepsType = 'Google_Service_Analytics_GoalUrlDestinationDetailsSteps';
  protected $stepsDataType = 'array';
  public $url;


  public function setCaseSensitive($caseSensitive)
  {
    $this->caseSensitive = $caseSensitive;
  }
  public function getCaseSensitive()
  {
    return $this->caseSensitive;
  }
  public function setFirstStepRequired($firstStepRequired)
  {
    $this->firstStepRequired = $firstStepRequired;
  }
  public function getFirstStepRequired()
  {
    return $this->firstStepRequired;
  }
  public function setMatchType($matchType)
  {
    $this->matchType = $matchType;
  }
  public function getMatchType()
  {
    return $this->matchType;
  }
  public function setSteps($steps)
  {
    $this->steps = $steps;
  }
  public function getSteps()
  {
    return $this->steps;
  }
  public function setUrl($url)
  {
    $this->url = $url;
  }
  public function getUrl()
  {
    return $this->url;
  }
}

class Google_Service_Analytics_GoalUrlDestinationDetailsSteps extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $name;
  public $number;
  public $url;


  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setNumber($number)
  {
    $this->number = $number;
  }
  public function getNumber()
  {
    return $this->number;
  }
  public function setUrl($url)
  {
    $this->url = $url;
  }
  public function getUrl()
  {
    return $this->url;
  }
}

class Google_Service_Analytics_GoalVisitNumPagesDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $comparisonType;
  public $comparisonValue;


  public function setComparisonType($comparisonType)
  {
    $this->comparisonType = $comparisonType;
  }
  public function getComparisonType()
  {
    return $this->comparisonType;
  }
  public function setComparisonValue($comparisonValue)
  {
    $this->comparisonValue = $comparisonValue;
  }
  public function getComparisonValue()
  {
    return $this->comparisonValue;
  }
}

class Google_Service_Analytics_GoalVisitTimeOnSiteDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $comparisonType;
  public $comparisonValue;


  public function setComparisonType($comparisonType)
  {
    $this->comparisonType = $comparisonType;
  }
  public function getComparisonType()
  {
    return $this->comparisonType;
  }
  public function setComparisonValue($comparisonValue)
  {
    $this->comparisonValue = $comparisonValue;
  }
  public function getComparisonValue()
  {
    return $this->comparisonValue;
  }
}

class Google_Service_Analytics_Goals extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Goal';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_McfData extends Google_Collection
{
  protected $collection_key = 'rows';
  protected $internal_gapi_mappings = array(
  );
  protected $columnHeadersType = 'Google_Service_Analytics_McfDataColumnHeaders';
  protected $columnHeadersDataType = 'array';
  public $containsSampledData;
  public $id;
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  protected $profileInfoType = 'Google_Service_Analytics_McfDataProfileInfo';
  protected $profileInfoDataType = '';
  protected $queryType = 'Google_Service_Analytics_McfDataQuery';
  protected $queryDataType = '';
  protected $rowsType = 'Google_Service_Analytics_McfDataRows';
  protected $rowsDataType = 'array';
  public $sampleSize;
  public $sampleSpace;
  public $selfLink;
  public $totalResults;
  public $totalsForAllResults;


  public function setColumnHeaders($columnHeaders)
  {
    $this->columnHeaders = $columnHeaders;
  }
  public function getColumnHeaders()
  {
    return $this->columnHeaders;
  }
  public function setContainsSampledData($containsSampledData)
  {
    $this->containsSampledData = $containsSampledData;
  }
  public function getContainsSampledData()
  {
    return $this->containsSampledData;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setProfileInfo(Google_Service_Analytics_McfDataProfileInfo $profileInfo)
  {
    $this->profileInfo = $profileInfo;
  }
  public function getProfileInfo()
  {
    return $this->profileInfo;
  }
  public function setQuery(Google_Service_Analytics_McfDataQuery $query)
  {
    $this->query = $query;
  }
  public function getQuery()
  {
    return $this->query;
  }
  public function setRows($rows)
  {
    $this->rows = $rows;
  }
  public function getRows()
  {
    return $this->rows;
  }
  public function setSampleSize($sampleSize)
  {
    $this->sampleSize = $sampleSize;
  }
  public function getSampleSize()
  {
    return $this->sampleSize;
  }
  public function setSampleSpace($sampleSpace)
  {
    $this->sampleSpace = $sampleSpace;
  }
  public function getSampleSpace()
  {
    return $this->sampleSpace;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setTotalsForAllResults($totalsForAllResults)
  {
    $this->totalsForAllResults = $totalsForAllResults;
  }
  public function getTotalsForAllResults()
  {
    return $this->totalsForAllResults;
  }
}

class Google_Service_Analytics_McfDataColumnHeaders extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $columnType;
  public $dataType;
  public $name;


  public function setColumnType($columnType)
  {
    $this->columnType = $columnType;
  }
  public function getColumnType()
  {
    return $this->columnType;
  }
  public function setDataType($dataType)
  {
    $this->dataType = $dataType;
  }
  public function getDataType()
  {
    return $this->dataType;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_Analytics_McfDataProfileInfo extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $internalWebPropertyId;
  public $profileId;
  public $profileName;
  public $tableId;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setProfileId($profileId)
  {
    $this->profileId = $profileId;
  }
  public function getProfileId()
  {
    return $this->profileId;
  }
  public function setProfileName($profileName)
  {
    $this->profileName = $profileName;
  }
  public function getProfileName()
  {
    return $this->profileName;
  }
  public function setTableId($tableId)
  {
    $this->tableId = $tableId;
  }
  public function getTableId()
  {
    return $this->tableId;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_McfDataQuery extends Google_Collection
{
  protected $collection_key = 'sort';
  protected $internal_gapi_mappings = array(
        "endDate" => "end-date",
        "maxResults" => "max-results",
        "startDate" => "start-date",
        "startIndex" => "start-index",
  );
  public $dimensions;
  public $endDate;
  public $filters;
  public $ids;
  public $maxResults;
  public $metrics;
  public $samplingLevel;
  public $segment;
  public $sort;
  public $startDate;
  public $startIndex;


  public function setDimensions($dimensions)
  {
    $this->dimensions = $dimensions;
  }
  public function getDimensions()
  {
    return $this->dimensions;
  }
  public function setEndDate($endDate)
  {
    $this->endDate = $endDate;
  }
  public function getEndDate()
  {
    return $this->endDate;
  }
  public function setFilters($filters)
  {
    $this->filters = $filters;
  }
  public function getFilters()
  {
    return $this->filters;
  }
  public function setIds($ids)
  {
    $this->ids = $ids;
  }
  public function getIds()
  {
    return $this->ids;
  }
  public function setMaxResults($maxResults)
  {
    $this->maxResults = $maxResults;
  }
  public function getMaxResults()
  {
    return $this->maxResults;
  }
  public function setMetrics($metrics)
  {
    $this->metrics = $metrics;
  }
  public function getMetrics()
  {
    return $this->metrics;
  }
  public function setSamplingLevel($samplingLevel)
  {
    $this->samplingLevel = $samplingLevel;
  }
  public function getSamplingLevel()
  {
    return $this->samplingLevel;
  }
  public function setSegment($segment)
  {
    $this->segment = $segment;
  }
  public function getSegment()
  {
    return $this->segment;
  }
  public function setSort($sort)
  {
    $this->sort = $sort;
  }
  public function getSort()
  {
    return $this->sort;
  }
  public function setStartDate($startDate)
  {
    $this->startDate = $startDate;
  }
  public function getStartDate()
  {
    return $this->startDate;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
}

class Google_Service_Analytics_McfDataRows extends Google_Collection
{
  protected $collection_key = 'conversionPathValue';
  protected $internal_gapi_mappings = array(
  );
  protected $conversionPathValueType = 'Google_Service_Analytics_McfDataRowsConversionPathValue';
  protected $conversionPathValueDataType = 'array';
  public $primitiveValue;


  public function setConversionPathValue($conversionPathValue)
  {
    $this->conversionPathValue = $conversionPathValue;
  }
  public function getConversionPathValue()
  {
    return $this->conversionPathValue;
  }
  public function setPrimitiveValue($primitiveValue)
  {
    $this->primitiveValue = $primitiveValue;
  }
  public function getPrimitiveValue()
  {
    return $this->primitiveValue;
  }
}

class Google_Service_Analytics_McfDataRowsConversionPathValue extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $interactionType;
  public $nodeValue;


  public function setInteractionType($interactionType)
  {
    $this->interactionType = $interactionType;
  }
  public function getInteractionType()
  {
    return $this->interactionType;
  }
  public function setNodeValue($nodeValue)
  {
    $this->nodeValue = $nodeValue;
  }
  public function getNodeValue()
  {
    return $this->nodeValue;
  }
}

class Google_Service_Analytics_McfDataTotalsForAllResults extends Google_Model
{
}

class Google_Service_Analytics_Profile extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  protected $childLinkType = 'Google_Service_Analytics_ProfileChildLink';
  protected $childLinkDataType = '';
  public $created;
  public $currency;
  public $defaultPage;
  public $eCommerceTracking;
  public $enhancedECommerceTracking;
  public $excludeQueryParameters;
  public $id;
  public $internalWebPropertyId;
  public $kind;
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_ProfileParentLink';
  protected $parentLinkDataType = '';
  protected $permissionsType = 'Google_Service_Analytics_ProfilePermissions';
  protected $permissionsDataType = '';
  public $selfLink;
  public $siteSearchCategoryParameters;
  public $siteSearchQueryParameters;
  public $stripSiteSearchCategoryParameters;
  public $stripSiteSearchQueryParameters;
  public $timezone;
  public $type;
  public $updated;
  public $webPropertyId;
  public $websiteUrl;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setChildLink(Google_Service_Analytics_ProfileChildLink $childLink)
  {
    $this->childLink = $childLink;
  }
  public function getChildLink()
  {
    return $this->childLink;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setCurrency($currency)
  {
    $this->currency = $currency;
  }
  public function getCurrency()
  {
    return $this->currency;
  }
  public function setDefaultPage($defaultPage)
  {
    $this->defaultPage = $defaultPage;
  }
  public function getDefaultPage()
  {
    return $this->defaultPage;
  }
  public function setECommerceTracking($eCommerceTracking)
  {
    $this->eCommerceTracking = $eCommerceTracking;
  }
  public function getECommerceTracking()
  {
    return $this->eCommerceTracking;
  }
  public function setEnhancedECommerceTracking($enhancedECommerceTracking)
  {
    $this->enhancedECommerceTracking = $enhancedECommerceTracking;
  }
  public function getEnhancedECommerceTracking()
  {
    return $this->enhancedECommerceTracking;
  }
  public function setExcludeQueryParameters($excludeQueryParameters)
  {
    $this->excludeQueryParameters = $excludeQueryParameters;
  }
  public function getExcludeQueryParameters()
  {
    return $this->excludeQueryParameters;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_ProfileParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setPermissions(Google_Service_Analytics_ProfilePermissions $permissions)
  {
    $this->permissions = $permissions;
  }
  public function getPermissions()
  {
    return $this->permissions;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setSiteSearchCategoryParameters($siteSearchCategoryParameters)
  {
    $this->siteSearchCategoryParameters = $siteSearchCategoryParameters;
  }
  public function getSiteSearchCategoryParameters()
  {
    return $this->siteSearchCategoryParameters;
  }
  public function setSiteSearchQueryParameters($siteSearchQueryParameters)
  {
    $this->siteSearchQueryParameters = $siteSearchQueryParameters;
  }
  public function getSiteSearchQueryParameters()
  {
    return $this->siteSearchQueryParameters;
  }
  public function setStripSiteSearchCategoryParameters($stripSiteSearchCategoryParameters)
  {
    $this->stripSiteSearchCategoryParameters = $stripSiteSearchCategoryParameters;
  }
  public function getStripSiteSearchCategoryParameters()
  {
    return $this->stripSiteSearchCategoryParameters;
  }
  public function setStripSiteSearchQueryParameters($stripSiteSearchQueryParameters)
  {
    $this->stripSiteSearchQueryParameters = $stripSiteSearchQueryParameters;
  }
  public function getStripSiteSearchQueryParameters()
  {
    return $this->stripSiteSearchQueryParameters;
  }
  public function setTimezone($timezone)
  {
    $this->timezone = $timezone;
  }
  public function getTimezone()
  {
    return $this->timezone;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
  public function setWebsiteUrl($websiteUrl)
  {
    $this->websiteUrl = $websiteUrl;
  }
  public function getWebsiteUrl()
  {
    return $this->websiteUrl;
  }
}

class Google_Service_Analytics_ProfileChildLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_ProfileFilterLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  protected $filterRefType = 'Google_Service_Analytics_FilterRef';
  protected $filterRefDataType = '';
  public $id;
  public $kind;
  protected $profileRefType = 'Google_Service_Analytics_ProfileRef';
  protected $profileRefDataType = '';
  public $rank;
  public $selfLink;


  public function setFilterRef(Google_Service_Analytics_FilterRef $filterRef)
  {
    $this->filterRef = $filterRef;
  }
  public function getFilterRef()
  {
    return $this->filterRef;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setProfileRef(Google_Service_Analytics_ProfileRef $profileRef)
  {
    $this->profileRef = $profileRef;
  }
  public function getProfileRef()
  {
    return $this->profileRef;
  }
  public function setRank($rank)
  {
    $this->rank = $rank;
  }
  public function getRank()
  {
    return $this->rank;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
}

class Google_Service_Analytics_ProfileFilterLinks extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_ProfileFilterLink';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_ProfileParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_ProfilePermissions extends Google_Collection
{
  protected $collection_key = 'effective';
  protected $internal_gapi_mappings = array(
  );
  public $effective;


  public function setEffective($effective)
  {
    $this->effective = $effective;
  }
  public function getEffective()
  {
    return $this->effective;
  }
}

class Google_Service_Analytics_ProfileRef extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $href;
  public $id;
  public $internalWebPropertyId;
  public $kind;
  public $name;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_ProfileSummary extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $kind;
  public $name;
  public $type;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_Profiles extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Profile';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_RealtimeData extends Google_Collection
{
  protected $collection_key = 'rows';
  protected $internal_gapi_mappings = array(
  );
  protected $columnHeadersType = 'Google_Service_Analytics_RealtimeDataColumnHeaders';
  protected $columnHeadersDataType = 'array';
  public $id;
  public $kind;
  protected $profileInfoType = 'Google_Service_Analytics_RealtimeDataProfileInfo';
  protected $profileInfoDataType = '';
  protected $queryType = 'Google_Service_Analytics_RealtimeDataQuery';
  protected $queryDataType = '';
  public $rows;
  public $selfLink;
  public $totalResults;
  public $totalsForAllResults;


  public function setColumnHeaders($columnHeaders)
  {
    $this->columnHeaders = $columnHeaders;
  }
  public function getColumnHeaders()
  {
    return $this->columnHeaders;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setProfileInfo(Google_Service_Analytics_RealtimeDataProfileInfo $profileInfo)
  {
    $this->profileInfo = $profileInfo;
  }
  public function getProfileInfo()
  {
    return $this->profileInfo;
  }
  public function setQuery(Google_Service_Analytics_RealtimeDataQuery $query)
  {
    $this->query = $query;
  }
  public function getQuery()
  {
    return $this->query;
  }
  public function setRows($rows)
  {
    $this->rows = $rows;
  }
  public function getRows()
  {
    return $this->rows;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setTotalsForAllResults($totalsForAllResults)
  {
    $this->totalsForAllResults = $totalsForAllResults;
  }
  public function getTotalsForAllResults()
  {
    return $this->totalsForAllResults;
  }
}

class Google_Service_Analytics_RealtimeDataColumnHeaders extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $columnType;
  public $dataType;
  public $name;


  public function setColumnType($columnType)
  {
    $this->columnType = $columnType;
  }
  public function getColumnType()
  {
    return $this->columnType;
  }
  public function setDataType($dataType)
  {
    $this->dataType = $dataType;
  }
  public function getDataType()
  {
    return $this->dataType;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_Analytics_RealtimeDataProfileInfo extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $internalWebPropertyId;
  public $profileId;
  public $profileName;
  public $tableId;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setProfileId($profileId)
  {
    $this->profileId = $profileId;
  }
  public function getProfileId()
  {
    return $this->profileId;
  }
  public function setProfileName($profileName)
  {
    $this->profileName = $profileName;
  }
  public function getProfileName()
  {
    return $this->profileName;
  }
  public function setTableId($tableId)
  {
    $this->tableId = $tableId;
  }
  public function getTableId()
  {
    return $this->tableId;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_RealtimeDataQuery extends Google_Collection
{
  protected $collection_key = 'sort';
  protected $internal_gapi_mappings = array(
        "maxResults" => "max-results",
  );
  public $dimensions;
  public $filters;
  public $ids;
  public $maxResults;
  public $metrics;
  public $sort;


  public function setDimensions($dimensions)
  {
    $this->dimensions = $dimensions;
  }
  public function getDimensions()
  {
    return $this->dimensions;
  }
  public function setFilters($filters)
  {
    $this->filters = $filters;
  }
  public function getFilters()
  {
    return $this->filters;
  }
  public function setIds($ids)
  {
    $this->ids = $ids;
  }
  public function getIds()
  {
    return $this->ids;
  }
  public function setMaxResults($maxResults)
  {
    $this->maxResults = $maxResults;
  }
  public function getMaxResults()
  {
    return $this->maxResults;
  }
  public function setMetrics($metrics)
  {
    $this->metrics = $metrics;
  }
  public function getMetrics()
  {
    return $this->metrics;
  }
  public function setSort($sort)
  {
    $this->sort = $sort;
  }
  public function getSort()
  {
    return $this->sort;
  }
}

class Google_Service_Analytics_RealtimeDataTotalsForAllResults extends Google_Model
{
}

class Google_Service_Analytics_Segment extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $created;
  public $definition;
  public $id;
  public $kind;
  public $name;
  public $segmentId;
  public $selfLink;
  public $type;
  public $updated;


  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setDefinition($definition)
  {
    $this->definition = $definition;
  }
  public function getDefinition()
  {
    return $this->definition;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setSegmentId($segmentId)
  {
    $this->segmentId = $segmentId;
  }
  public function getSegmentId()
  {
    return $this->segmentId;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
}

class Google_Service_Analytics_Segments extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Segment';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_UnsampledReport extends Google_Model
{
  protected $internal_gapi_mappings = array(
        "endDate" => "end-date",
        "startDate" => "start-date",
  );
  public $accountId;
  protected $cloudStorageDownloadDetailsType = 'Google_Service_Analytics_UnsampledReportCloudStorageDownloadDetails';
  protected $cloudStorageDownloadDetailsDataType = '';
  public $created;
  public $dimensions;
  public $downloadType;
  protected $driveDownloadDetailsType = 'Google_Service_Analytics_UnsampledReportDriveDownloadDetails';
  protected $driveDownloadDetailsDataType = '';
  public $endDate;
  public $filters;
  public $id;
  public $kind;
  public $metrics;
  public $profileId;
  public $segment;
  public $selfLink;
  public $startDate;
  public $status;
  public $title;
  public $updated;
  public $webPropertyId;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setCloudStorageDownloadDetails(Google_Service_Analytics_UnsampledReportCloudStorageDownloadDetails $cloudStorageDownloadDetails)
  {
    $this->cloudStorageDownloadDetails = $cloudStorageDownloadDetails;
  }
  public function getCloudStorageDownloadDetails()
  {
    return $this->cloudStorageDownloadDetails;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setDimensions($dimensions)
  {
    $this->dimensions = $dimensions;
  }
  public function getDimensions()
  {
    return $this->dimensions;
  }
  public function setDownloadType($downloadType)
  {
    $this->downloadType = $downloadType;
  }
  public function getDownloadType()
  {
    return $this->downloadType;
  }
  public function setDriveDownloadDetails(Google_Service_Analytics_UnsampledReportDriveDownloadDetails $driveDownloadDetails)
  {
    $this->driveDownloadDetails = $driveDownloadDetails;
  }
  public function getDriveDownloadDetails()
  {
    return $this->driveDownloadDetails;
  }
  public function setEndDate($endDate)
  {
    $this->endDate = $endDate;
  }
  public function getEndDate()
  {
    return $this->endDate;
  }
  public function setFilters($filters)
  {
    $this->filters = $filters;
  }
  public function getFilters()
  {
    return $this->filters;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setMetrics($metrics)
  {
    $this->metrics = $metrics;
  }
  public function getMetrics()
  {
    return $this->metrics;
  }
  public function setProfileId($profileId)
  {
    $this->profileId = $profileId;
  }
  public function getProfileId()
  {
    return $this->profileId;
  }
  public function setSegment($segment)
  {
    $this->segment = $segment;
  }
  public function getSegment()
  {
    return $this->segment;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setStartDate($startDate)
  {
    $this->startDate = $startDate;
  }
  public function getStartDate()
  {
    return $this->startDate;
  }
  public function setStatus($status)
  {
    $this->status = $status;
  }
  public function getStatus()
  {
    return $this->status;
  }
  public function setTitle($title)
  {
    $this->title = $title;
  }
  public function getTitle()
  {
    return $this->title;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setWebPropertyId($webPropertyId)
  {
    $this->webPropertyId = $webPropertyId;
  }
  public function getWebPropertyId()
  {
    return $this->webPropertyId;
  }
}

class Google_Service_Analytics_UnsampledReportCloudStorageDownloadDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $bucketId;
  public $objectId;


  public function setBucketId($bucketId)
  {
    $this->bucketId = $bucketId;
  }
  public function getBucketId()
  {
    return $this->bucketId;
  }
  public function setObjectId($objectId)
  {
    $this->objectId = $objectId;
  }
  public function getObjectId()
  {
    return $this->objectId;
  }
}

class Google_Service_Analytics_UnsampledReportDriveDownloadDetails extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $documentId;


  public function setDocumentId($documentId)
  {
    $this->documentId = $documentId;
  }
  public function getDocumentId()
  {
    return $this->documentId;
  }
}

class Google_Service_Analytics_UnsampledReports extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_UnsampledReport';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_Upload extends Google_Collection
{
  protected $collection_key = 'errors';
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $customDataSourceId;
  public $errors;
  public $id;
  public $kind;
  public $status;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setCustomDataSourceId($customDataSourceId)
  {
    $this->customDataSourceId = $customDataSourceId;
  }
  public function getCustomDataSourceId()
  {
    return $this->customDataSourceId;
  }
  public function setErrors($errors)
  {
    $this->errors = $errors;
  }
  public function getErrors()
  {
    return $this->errors;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setStatus($status)
  {
    $this->status = $status;
  }
  public function getStatus()
  {
    return $this->status;
  }
}

class Google_Service_Analytics_Uploads extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Upload';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
}

class Google_Service_Analytics_UserRef extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $email;
  public $id;
  public $kind;


  public function setEmail($email)
  {
    $this->email = $email;
  }
  public function getEmail()
  {
    return $this->email;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
}

class Google_Service_Analytics_WebPropertyRef extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  public $href;
  public $id;
  public $internalWebPropertyId;
  public $kind;
  public $name;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
}

class Google_Service_Analytics_WebPropertySummary extends Google_Collection
{
  protected $collection_key = 'profiles';
  protected $internal_gapi_mappings = array(
  );
  public $id;
  public $internalWebPropertyId;
  public $kind;
  public $level;
  public $name;
  protected $profilesType = 'Google_Service_Analytics_ProfileSummary';
  protected $profilesDataType = 'array';
  public $websiteUrl;


  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setLevel($level)
  {
    $this->level = $level;
  }
  public function getLevel()
  {
    return $this->level;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setProfiles($profiles)
  {
    $this->profiles = $profiles;
  }
  public function getProfiles()
  {
    return $this->profiles;
  }
  public function setWebsiteUrl($websiteUrl)
  {
    $this->websiteUrl = $websiteUrl;
  }
  public function getWebsiteUrl()
  {
    return $this->websiteUrl;
  }
}

class Google_Service_Analytics_Webproperties extends Google_Collection
{
  protected $collection_key = 'items';
  protected $internal_gapi_mappings = array(
  );
  protected $itemsType = 'Google_Service_Analytics_Webproperty';
  protected $itemsDataType = 'array';
  public $itemsPerPage;
  public $kind;
  public $nextLink;
  public $previousLink;
  public $startIndex;
  public $totalResults;
  public $username;


  public function setItems($items)
  {
    $this->items = $items;
  }
  public function getItems()
  {
    return $this->items;
  }
  public function setItemsPerPage($itemsPerPage)
  {
    $this->itemsPerPage = $itemsPerPage;
  }
  public function getItemsPerPage()
  {
    return $this->itemsPerPage;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setNextLink($nextLink)
  {
    $this->nextLink = $nextLink;
  }
  public function getNextLink()
  {
    return $this->nextLink;
  }
  public function setPreviousLink($previousLink)
  {
    $this->previousLink = $previousLink;
  }
  public function getPreviousLink()
  {
    return $this->previousLink;
  }
  public function setStartIndex($startIndex)
  {
    $this->startIndex = $startIndex;
  }
  public function getStartIndex()
  {
    return $this->startIndex;
  }
  public function setTotalResults($totalResults)
  {
    $this->totalResults = $totalResults;
  }
  public function getTotalResults()
  {
    return $this->totalResults;
  }
  public function setUsername($username)
  {
    $this->username = $username;
  }
  public function getUsername()
  {
    return $this->username;
  }
}

class Google_Service_Analytics_Webproperty extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $accountId;
  protected $childLinkType = 'Google_Service_Analytics_WebpropertyChildLink';
  protected $childLinkDataType = '';
  public $created;
  public $defaultProfileId;
  public $id;
  public $industryVertical;
  public $internalWebPropertyId;
  public $kind;
  public $level;
  public $name;
  protected $parentLinkType = 'Google_Service_Analytics_WebpropertyParentLink';
  protected $parentLinkDataType = '';
  protected $permissionsType = 'Google_Service_Analytics_WebpropertyPermissions';
  protected $permissionsDataType = '';
  public $profileCount;
  public $selfLink;
  public $updated;
  public $websiteUrl;


  public function setAccountId($accountId)
  {
    $this->accountId = $accountId;
  }
  public function getAccountId()
  {
    return $this->accountId;
  }
  public function setChildLink(Google_Service_Analytics_WebpropertyChildLink $childLink)
  {
    $this->childLink = $childLink;
  }
  public function getChildLink()
  {
    return $this->childLink;
  }
  public function setCreated($created)
  {
    $this->created = $created;
  }
  public function getCreated()
  {
    return $this->created;
  }
  public function setDefaultProfileId($defaultProfileId)
  {
    $this->defaultProfileId = $defaultProfileId;
  }
  public function getDefaultProfileId()
  {
    return $this->defaultProfileId;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setIndustryVertical($industryVertical)
  {
    $this->industryVertical = $industryVertical;
  }
  public function getIndustryVertical()
  {
    return $this->industryVertical;
  }
  public function setInternalWebPropertyId($internalWebPropertyId)
  {
    $this->internalWebPropertyId = $internalWebPropertyId;
  }
  public function getInternalWebPropertyId()
  {
    return $this->internalWebPropertyId;
  }
  public function setKind($kind)
  {
    $this->kind = $kind;
  }
  public function getKind()
  {
    return $this->kind;
  }
  public function setLevel($level)
  {
    $this->level = $level;
  }
  public function getLevel()
  {
    return $this->level;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setParentLink(Google_Service_Analytics_WebpropertyParentLink $parentLink)
  {
    $this->parentLink = $parentLink;
  }
  public function getParentLink()
  {
    return $this->parentLink;
  }
  public function setPermissions(Google_Service_Analytics_WebpropertyPermissions $permissions)
  {
    $this->permissions = $permissions;
  }
  public function getPermissions()
  {
    return $this->permissions;
  }
  public function setProfileCount($profileCount)
  {
    $this->profileCount = $profileCount;
  }
  public function getProfileCount()
  {
    return $this->profileCount;
  }
  public function setSelfLink($selfLink)
  {
    $this->selfLink = $selfLink;
  }
  public function getSelfLink()
  {
    return $this->selfLink;
  }
  public function setUpdated($updated)
  {
    $this->updated = $updated;
  }
  public function getUpdated()
  {
    return $this->updated;
  }
  public function setWebsiteUrl($websiteUrl)
  {
    $this->websiteUrl = $websiteUrl;
  }
  public function getWebsiteUrl()
  {
    return $this->websiteUrl;
  }
}

class Google_Service_Analytics_WebpropertyChildLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_WebpropertyParentLink extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $href;
  public $type;


  public function setHref($href)
  {
    $this->href = $href;
  }
  public function getHref()
  {
    return $this->href;
  }
  public function setType($type)
  {
    $this->type = $type;
  }
  public function getType()
  {
    return $this->type;
  }
}

class Google_Service_Analytics_WebpropertyPermissions extends Google_Collection
{
  protected $collection_key = 'effective';
  protected $internal_gapi_mappings = array(
  );
  public $effective;


  public function setEffective($effective)
  {
    $this->effective = $effective;
  }
  public function getEffective()
  {
    return $this->effective;
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_Service_Exception extends Google_Exception implements Google_Task_Retryable
{
  /**
   * Optional list of errors returned in a JSON body of an HTTP error response.
   */
  protected $errors = array();

  /**
   * @var array $retryMap Map of errors with retry counts.
   */
  private $retryMap = array();

  /**
   * Override default constructor to add the ability to set $errors and a retry
   * map.
   *
   * @param string $message
   * @param int $code
   * @param Exception|null $previous
   * @param [{string, string}] errors List of errors returned in an HTTP
   * response.  Defaults to [].
   * @param array|null $retryMap Map of errors with retry counts.
   */
  public function __construct(
      $message,
      $code = 0,
      Exception $previous = null,
      $errors = array(),
      array $retryMap = null
  ) {
    if (version_compare(PHP_VERSION, '5.3.0') >= 0) {
      parent::__construct($message, $code, $previous);
    } else {
      parent::__construct($message, $code);
    }

    $this->errors = $errors;

    if (is_array($retryMap)) {
      $this->retryMap = $retryMap;
    }
  }

  /**
   * An example of the possible errors returned.
   *
   * {
   *   "domain": "global",
   *   "reason": "authError",
   *   "message": "Invalid Credentials",
   *   "locationType": "header",
   *   "location": "Authorization",
   * }
   *
   * @return [{string, string}] List of errors return in an HTTP response or [].
   */
  public function getErrors()
  {
    return $this->errors;
  }

  /**
   * Gets the number of times the associated task can be retried.
   *
   * NOTE: -1 is returned if the task can be retried indefinitely
   *
   * @return integer
   */
  public function allowedRetries()
  {
    if (isset($this->retryMap[$this->code])) {
      return $this->retryMap[$this->code];
    }

    $errors = $this->getErrors();

    if (!empty($errors) && isset($errors[0]['reason']) &&
        isset($this->retryMap[$errors[0]['reason']])) {
      return $this->retryMap[$errors[0]['reason']];
    }

    return 0;
  }
}
 
/*
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

/**
 * Service definition for Oauth2 (v2).
 *
 * <p>
 * Lets you access OAuth2 protocol related APIs.</p>
 *
 * <p>
 * For more information about this service, see the API
 * <a href="https://developers.google.com/accounts/docs/OAuth2" target="_blank">Documentation</a>
 * </p>
 *
 * @author Google, Inc.
 */
class Google_Service_Oauth2 extends Google_Service
{
  /** Know your basic profile info and list of people in your circles.. */
  const PLUS_LOGIN =
      "https://www.googleapis.com/auth/plus.login";
  /** Know who you are on Google. */
  const PLUS_ME =
      "https://www.googleapis.com/auth/plus.me";
  /** View your email address. */
  const USERINFO_EMAIL =
      "https://www.googleapis.com/auth/userinfo.email";
  /** View your basic profile info. */
  const USERINFO_PROFILE =
      "https://www.googleapis.com/auth/userinfo.profile";

  public $userinfo;
  public $userinfo_v2_me;
  private $base_methods;

  /**
   * Constructs the internal representation of the Oauth2 service.
   *
   * @param Google_Client $client
   */
  public function __construct(Google_Client $client)
  {
    parent::__construct($client);
    $this->servicePath = '';
    $this->version = 'v2';
    $this->serviceName = 'oauth2';

    $this->userinfo = new Google_Service_Oauth2_Userinfo_Resource(
        $this,
        $this->serviceName,
        'userinfo',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'oauth2/v2/userinfo',
              'httpMethod' => 'GET',
              'parameters' => array(),
            ),
          )
        )
    );
    $this->userinfo_v2_me = new Google_Service_Oauth2_UserinfoV2Me_Resource(
        $this,
        $this->serviceName,
        'me',
        array(
          'methods' => array(
            'get' => array(
              'path' => 'userinfo/v2/me',
              'httpMethod' => 'GET',
              'parameters' => array(),
            ),
          )
        )
    );
    $this->base_methods = new Google_Service_Resource(
        $this,
        $this->serviceName,
        '',
        array(
          'methods' => array(
            'getCertForOpenIdConnect' => array(
              'path' => 'oauth2/v2/certs',
              'httpMethod' => 'GET',
              'parameters' => array(),
            ),'tokeninfo' => array(
              'path' => 'oauth2/v2/tokeninfo',
              'httpMethod' => 'POST',
              'parameters' => array(
                'access_token' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
                'id_token' => array(
                  'location' => 'query',
                  'type' => 'string',
                ),
              ),
            ),
          )
        )
    );
  }
  /**
   * (getCertForOpenIdConnect)
   *
   * @param array $optParams Optional parameters.
   * @return Google_Service_Oauth2_Jwk
   */
  public function getCertForOpenIdConnect($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->base_methods->call('getCertForOpenIdConnect', array($params), "Google_Service_Oauth2_Jwk");
  }
  /**
   * (tokeninfo)
   *
   * @param array $optParams Optional parameters.
   *
   * @opt_param string access_token
   * @opt_param string id_token
   * @return Google_Service_Oauth2_Tokeninfo
   */
  public function tokeninfo($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->base_methods->call('tokeninfo', array($params), "Google_Service_Oauth2_Tokeninfo");
  }
}


/**
 * The "userinfo" collection of methods.
 * Typical usage is:
 *  <code>
 *   $oauth2Service = new Google_Service_Oauth2(...);
 *   $userinfo = $oauth2Service->userinfo;
 *  </code>
 */
class Google_Service_Oauth2_Userinfo_Resource extends Google_Service_Resource
{

  /**
   * (userinfo.get)
   *
   * @param array $optParams Optional parameters.
   * @return Google_Service_Oauth2_Userinfoplus
   */
  public function get($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Oauth2_Userinfoplus");
  }
}

/**
 * The "v2" collection of methods.
 * Typical usage is:
 *  <code>
 *   $oauth2Service = new Google_Service_Oauth2(...);
 *   $v2 = $oauth2Service->v2;
 *  </code>
 */
class Google_Service_Oauth2_UserinfoV2_Resource extends Google_Service_Resource
{
}

/**
 * The "me" collection of methods.
 * Typical usage is:
 *  <code>
 *   $oauth2Service = new Google_Service_Oauth2(...);
 *   $me = $oauth2Service->me;
 *  </code>
 */
class Google_Service_Oauth2_UserinfoV2Me_Resource extends Google_Service_Resource
{

  /**
   * (me.get)
   *
   * @param array $optParams Optional parameters.
   * @return Google_Service_Oauth2_Userinfoplus
   */
  public function get($optParams = array())
  {
    $params = array();
    $params = array_merge($params, $optParams);
    return $this->call('get', array($params), "Google_Service_Oauth2_Userinfoplus");
  }
}




class Google_Service_Oauth2_Jwk extends Google_Collection
{
  protected $collection_key = 'keys';
  protected $internal_gapi_mappings = array(
  );
  protected $keysType = 'Google_Service_Oauth2_JwkKeys';
  protected $keysDataType = 'array';


  public function setKeys($keys)
  {
    $this->keys = $keys;
  }
  public function getKeys()
  {
    return $this->keys;
  }
}

class Google_Service_Oauth2_JwkKeys extends Google_Model
{
  protected $internal_gapi_mappings = array(
  );
  public $alg;
  public $e;
  public $kid;
  public $kty;
  public $n;
  public $use;


  public function setAlg($alg)
  {
    $this->alg = $alg;
  }
  public function getAlg()
  {
    return $this->alg;
  }
  public function setE($e)
  {
    $this->e = $e;
  }
  public function getE()
  {
    return $this->e;
  }
  public function setKid($kid)
  {
    $this->kid = $kid;
  }
  public function getKid()
  {
    return $this->kid;
  }
  public function setKty($kty)
  {
    $this->kty = $kty;
  }
  public function getKty()
  {
    return $this->kty;
  }
  public function setN($n)
  {
    $this->n = $n;
  }
  public function getN()
  {
    return $this->n;
  }
  public function setUse($use)
  {
    $this->use = $use;
  }
  public function getUse()
  {
    return $this->use;
  }
}

class Google_Service_Oauth2_Tokeninfo extends Google_Model
{
  protected $internal_gapi_mappings = array(
        "accessType" => "access_type",
        "expiresIn" => "expires_in",
        "issuedTo" => "issued_to",
        "userId" => "user_id",
        "verifiedEmail" => "verified_email",
  );
  public $accessType;
  public $audience;
  public $email;
  public $expiresIn;
  public $issuedTo;
  public $scope;
  public $userId;
  public $verifiedEmail;


  public function setAccessType($accessType)
  {
    $this->accessType = $accessType;
  }
  public function getAccessType()
  {
    return $this->accessType;
  }
  public function setAudience($audience)
  {
    $this->audience = $audience;
  }
  public function getAudience()
  {
    return $this->audience;
  }
  public function setEmail($email)
  {
    $this->email = $email;
  }
  public function getEmail()
  {
    return $this->email;
  }
  public function setExpiresIn($expiresIn)
  {
    $this->expiresIn = $expiresIn;
  }
  public function getExpiresIn()
  {
    return $this->expiresIn;
  }
  public function setIssuedTo($issuedTo)
  {
    $this->issuedTo = $issuedTo;
  }
  public function getIssuedTo()
  {
    return $this->issuedTo;
  }
  public function setScope($scope)
  {
    $this->scope = $scope;
  }
  public function getScope()
  {
    return $this->scope;
  }
  public function setUserId($userId)
  {
    $this->userId = $userId;
  }
  public function getUserId()
  {
    return $this->userId;
  }
  public function setVerifiedEmail($verifiedEmail)
  {
    $this->verifiedEmail = $verifiedEmail;
  }
  public function getVerifiedEmail()
  {
    return $this->verifiedEmail;
  }
}

class Google_Service_Oauth2_Userinfoplus extends Google_Model
{
  protected $internal_gapi_mappings = array(
        "familyName" => "family_name",
        "givenName" => "given_name",
        "verifiedEmail" => "verified_email",
  );
  public $email;
  public $familyName;
  public $gender;
  public $givenName;
  public $hd;
  public $id;
  public $link;
  public $locale;
  public $name;
  public $picture;
  public $verifiedEmail;


  public function setEmail($email)
  {
    $this->email = $email;
  }
  public function getEmail()
  {
    return $this->email;
  }
  public function setFamilyName($familyName)
  {
    $this->familyName = $familyName;
  }
  public function getFamilyName()
  {
    return $this->familyName;
  }
  public function setGender($gender)
  {
    $this->gender = $gender;
  }
  public function getGender()
  {
    return $this->gender;
  }
  public function setGivenName($givenName)
  {
    $this->givenName = $givenName;
  }
  public function getGivenName()
  {
    return $this->givenName;
  }
  public function setHd($hd)
  {
    $this->hd = $hd;
  }
  public function getHd()
  {
    return $this->hd;
  }
  public function setId($id)
  {
    $this->id = $id;
  }
  public function getId()
  {
    return $this->id;
  }
  public function setLink($link)
  {
    $this->link = $link;
  }
  public function getLink()
  {
    return $this->link;
  }
  public function setLocale($locale)
  {
    $this->locale = $locale;
  }
  public function getLocale()
  {
    return $this->locale;
  }
  public function setName($name)
  {
    $this->name = $name;
  }
  public function getName()
  {
    return $this->name;
  }
  public function setPicture($picture)
  {
    $this->picture = $picture;
  }
  public function getPicture()
  {
    return $this->picture;
  }
  public function setVerifiedEmail($verifiedEmail)
  {
    $this->verifiedEmail = $verifiedEmail;
  }
  public function getVerifiedEmail()
  {
    return $this->verifiedEmail;
  }
}
 
/**
 * Copyright 2010 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Implements the actual methods/resources of the discovered Google API using magic function
 * calling overloading (__call()), which on call will see if the method name (plus.activities.list)
 * is available in this service, and if so construct an apiHttpRequest representing it.
 *
 */
class Google_Service_Resource
{
  // Valid query parameters that work, but don't appear in discovery.
  private $stackParameters = array(
      'alt' => array('type' => 'string', 'location' => 'query'),
      'fields' => array('type' => 'string', 'location' => 'query'),
      'trace' => array('type' => 'string', 'location' => 'query'),
      'userIp' => array('type' => 'string', 'location' => 'query'),
      'userip' => array('type' => 'string', 'location' => 'query'),
      'quotaUser' => array('type' => 'string', 'location' => 'query'),
      'data' => array('type' => 'string', 'location' => 'body'),
      'mimeType' => array('type' => 'string', 'location' => 'header'),
      'uploadType' => array('type' => 'string', 'location' => 'query'),
      'mediaUpload' => array('type' => 'complex', 'location' => 'query'),
      'prettyPrint' => array('type' => 'string', 'location' => 'query'),
  );

  /** @var Google_Service $service */
  private $service;

  /** @var Google_Client $client */
  private $client;

  /** @var string $serviceName */
  private $serviceName;

  /** @var string $resourceName */
  private $resourceName;

  /** @var array $methods */
  private $methods;

  public function __construct($service, $serviceName, $resourceName, $resource)
  {
    $this->service = $service;
    $this->client = $service->getClient();
    $this->serviceName = $serviceName;
    $this->resourceName = $resourceName;
    $this->methods = isset($resource['methods']) ?
        $resource['methods'] :
        array($resourceName => $resource);
  }

  /**
   * TODO(ianbarber): This function needs simplifying.
   * @param $name
   * @param $arguments
   * @param $expected_class - optional, the expected class name
   * @return Google_Http_Request|expected_class
   * @throws Google_Exception
   */
  public function call($name, $arguments, $expected_class = null)
  {
    if (! isset($this->methods[$name])) {
      $this->client->getLogger()->error(
          'Service method unknown',
          array(
              'service' => $this->serviceName,
              'resource' => $this->resourceName,
              'method' => $name
          )
      );

      throw new Google_Exception(
          "Unknown function: " .
          "{$this->serviceName}->{$this->resourceName}->{$name}()"
      );
    }
    $method = $this->methods[$name];
    $parameters = $arguments[0];

    // postBody is a special case since it's not defined in the discovery
    // document as parameter, but we abuse the param entry for storing it.
    $postBody = null;
    if (isset($parameters['postBody'])) {
      if ($parameters['postBody'] instanceof Google_Model) {
        // In the cases the post body is an existing object, we want
        // to use the smart method to create a simple object for
        // for JSONification.
        $parameters['postBody'] = $parameters['postBody']->toSimpleObject();
      } else if (is_object($parameters['postBody'])) {
        // If the post body is another kind of object, we will try and
        // wrangle it into a sensible format.
        $parameters['postBody'] =
            $this->convertToArrayAndStripNulls($parameters['postBody']);
      }
      $postBody = json_encode($parameters['postBody']);
      unset($parameters['postBody']);
    }

    // TODO(ianbarber): optParams here probably should have been
    // handled already - this may well be redundant code.
    if (isset($parameters['optParams'])) {
      $optParams = $parameters['optParams'];
      unset($parameters['optParams']);
      $parameters = array_merge($parameters, $optParams);
    }

    if (!isset($method['parameters'])) {
      $method['parameters'] = array();
    }

    $method['parameters'] = array_merge(
        $method['parameters'],
        $this->stackParameters
    );
    foreach ($parameters as $key => $val) {
      if ($key != 'postBody' && ! isset($method['parameters'][$key])) {
        $this->client->getLogger()->error(
            'Service parameter unknown',
            array(
                'service' => $this->serviceName,
                'resource' => $this->resourceName,
                'method' => $name,
                'parameter' => $key
            )
        );
        throw new Google_Exception("($name) unknown parameter: '$key'");
      }
    }

    foreach ($method['parameters'] as $paramName => $paramSpec) {
      if (isset($paramSpec['required']) &&
          $paramSpec['required'] &&
          ! isset($parameters[$paramName])
      ) {
        $this->client->getLogger()->error(
            'Service parameter missing',
            array(
                'service' => $this->serviceName,
                'resource' => $this->resourceName,
                'method' => $name,
                'parameter' => $paramName
            )
        );
        throw new Google_Exception("($name) missing required param: '$paramName'");
      }
      if (isset($parameters[$paramName])) {
        $value = $parameters[$paramName];
        $parameters[$paramName] = $paramSpec;
        $parameters[$paramName]['value'] = $value;
        unset($parameters[$paramName]['required']);
      } else {
        // Ensure we don't pass nulls.
        unset($parameters[$paramName]);
      }
    }

    $servicePath = $this->service->servicePath;

    $this->client->getLogger()->info(
        'Service Call',
        array(
            'service' => $this->serviceName,
            'resource' => $this->resourceName,
            'method' => $name,
            'arguments' => $parameters,
        )
    );

    $url = Google_Http_REST::createRequestUri(
        $servicePath,
        $method['path'],
        $parameters
    );
    $httpRequest = new Google_Http_Request(
        $url,
        $method['httpMethod'],
        null,
        $postBody
    );
    $httpRequest->setBaseComponent($this->client->getBasePath());

    if ($postBody) {
      $contentTypeHeader = array();
      $contentTypeHeader['content-type'] = 'application/json; charset=UTF-8';
      $httpRequest->setRequestHeaders($contentTypeHeader);
      $httpRequest->setPostBody($postBody);
    }

    $httpRequest = $this->client->getAuth()->sign($httpRequest);
    $httpRequest->setExpectedClass($expected_class);

    if (isset($parameters['data']) &&
        ($parameters['uploadType']['value'] == 'media' || $parameters['uploadType']['value'] == 'multipart')) {
      // If we are doing a simple media upload, trigger that as a convenience.
      $mfu = new Google_Http_MediaFileUpload(
          $this->client,
          $httpRequest,
          isset($parameters['mimeType']) ? $parameters['mimeType']['value'] : 'application/octet-stream',
          $parameters['data']['value']
      );
    }

    if (isset($parameters['alt']) && $parameters['alt']['value'] == 'media') {
      $httpRequest->enableExpectedRaw();
    }

    if ($this->client->shouldDefer()) {
      // If we are in batch or upload mode, return the raw request.
      return $httpRequest;
    }

    return $this->client->execute($httpRequest);
  }

  protected function convertToArrayAndStripNulls($o)
  {
    $o = (array) $o;
    foreach ($o as $k => $v) {
      if ($v === null) {
        unset($o[$k]);
      } elseif (is_object($v) || is_array($v)) {
        $o[$k] = $this->convertToArrayAndStripNulls($o[$k]);
      }
    }
    return $o;
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_Task_Exception extends Google_Exception
{
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * Interface for checking how many times a given task can be retried following
 * a failure.
 */
interface Google_Task_Retryable
{
  /**
   * Gets the number of times the associated task can be retried.
   *
   * NOTE: -1 is returned if the task can be retried indefinitely
   *
   * @return integer
   */
  public function allowedRetries();
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

/**
 * A task runner with exponential backoff support.
 *
 * @see https://developers.google.com/drive/web/handle-errors#implementing_exponential_backoff
 */
class Google_Task_Runner
{
  /**
   * @var integer $maxDelay The max time (in seconds) to wait before a retry.
   */
  private $maxDelay = 60;
  /**
   * @var integer $delay The previous delay from which the next is calculated.
   */
  private $delay = 1;

  /**
   * @var integer $factor The base number for the exponential back off.
   */
  private $factor = 2;
  /**
   * @var float $jitter A random number between -$jitter and $jitter will be
   * added to $factor on each iteration to allow for a better distribution of
   * retries.
   */
  private $jitter = 0.5;

  /**
   * @var integer $attempts The number of attempts that have been tried so far.
   */
  private $attempts = 0;
  /**
   * @var integer $maxAttempts The max number of attempts allowed.
   */
  private $maxAttempts = 1;

  /**
   * @var Google_Client $client The current API client.
   */
  private $client;

  /**
   * @var string $name The name of the current task (used for logging).
   */
  private $name;
  /**
   * @var callable $action The task to run and possibly retry.
   */
  private $action;
  /**
   * @var array $arguments The task arguments.
   */
  private $arguments;

  /**
   * Creates a new task runner with exponential backoff support.
   *
   * @param Google_Client $client The current API client
   * @param string $name The name of the current task (used for logging)
   * @param callable $action The task to run and possibly retry
   * @param array $arguments The task arguments
   * @throws Google_Task_Exception when misconfigured
   */
  public function __construct(
      Google_Client $client,
      $name,
      $action,
      array $arguments = array()
  ) {
    $config = (array) $client->getClassConfig('Google_Task_Runner');

    if (isset($config['initial_delay'])) {
      if ($config['initial_delay'] < 0) {
        throw new Google_Task_Exception(
            'Task configuration `initial_delay` must not be negative.'
        );
      }

      $this->delay = $config['initial_delay'];
    }

    if (isset($config['max_delay'])) {
      if ($config['max_delay'] <= 0) {
        throw new Google_Task_Exception(
            'Task configuration `max_delay` must be greater than 0.'
        );
      }

      $this->maxDelay = $config['max_delay'];
    }

    if (isset($config['factor'])) {
      if ($config['factor'] <= 0) {
        throw new Google_Task_Exception(
            'Task configuration `factor` must be greater than 0.'
        );
      }

      $this->factor = $config['factor'];
    }

    if (isset($config['jitter'])) {
      if ($config['jitter'] <= 0) {
        throw new Google_Task_Exception(
            'Task configuration `jitter` must be greater than 0.'
        );
      }

      $this->jitter = $config['jitter'];
    }

    if (isset($config['retries'])) {
      if ($config['retries'] < 0) {
        throw new Google_Task_Exception(
            'Task configuration `retries` must not be negative.'
        );
      }
      $this->maxAttempts += $config['retries'];
    }

    if (!is_callable($action)) {
        throw new Google_Task_Exception(
            'Task argument `$action` must be a valid callable.'
        );
    }

    $this->name = $name;
    $this->client = $client;
    $this->action = $action;
    $this->arguments = $arguments;
  }

  /**
   * Checks if a retry can be attempted.
   *
   * @return boolean
   */
  public function canAttmpt()
  {
    return $this->attempts < $this->maxAttempts;
  }

  /**
   * Runs the task and (if applicable) automatically retries when errors occur.
   *
   * @return mixed
   * @throws Google_Task_Retryable on failure when no retries are available.
   */
  public function run()
  {
    while ($this->attempt()) {
      try {
        return call_user_func_array($this->action, $this->arguments);
      } catch (Google_Task_Retryable $exception) {
        $allowedRetries = $exception->allowedRetries();

        if (!$this->canAttmpt() || !$allowedRetries) {
          throw $exception;
        }

        if ($allowedRetries > 0) {
          $this->maxAttempts = min(
              $this->maxAttempts,
              $this->attempts + $allowedRetries
          );
        }
      }
    }
  }

  /**
   * Runs a task once, if possible. This is useful for bypassing the `run()`
   * loop.
   *
   * NOTE: If this is not the first attempt, this function will sleep in
   * accordance to the backoff configurations before running the task.
   *
   * @return boolean
   */
  public function attempt()
  {
    if (!$this->canAttmpt()) {
      return false;
    }

    if ($this->attempts > 0) {
      $this->backOff();
    }

    $this->attempts++;
    return true;
  }

  /**
   * Sleeps in accordance to the backoff configurations.
   */
  private function backOff()
  {
    $delay = $this->getDelay();

    $this->client->getLogger()->debug(
        'Retrying task with backoff',
        array(
            'request' => $this->name,
            'retry' => $this->attempts,
            'backoff_seconds' => $delay
        )
    );

    usleep($delay * 1000000);
  }

  /**
   * Gets the delay (in seconds) for the current backoff period.
   *
   * @return float
   */
  private function getDelay()
  {
    $jitter = $this->getJitter();
    $factor = $this->attempts > 1 ? $this->factor + $jitter : 1 + abs($jitter);

    return $this->delay = min($this->maxDelay, $this->delay * $factor);
  }

  /**
   * Gets the current jitter (random number between -$this->jitter and
   * $this->jitter).
   *
   * @return float
   */
  private function getJitter()
  {
    return $this->jitter * 2 * mt_rand() / mt_getrandmax() - $this->jitter;
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Abstract IO base class
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

abstract class Google_IO_Abstract
{
  const UNKNOWN_CODE = 0;
  const FORM_URLENCODED = 'application/x-www-form-urlencoded';
  private static $CONNECTION_ESTABLISHED_HEADERS = array(
    "HTTP/1.0 200 Connection established\r\n\r\n",
    "HTTP/1.1 200 Connection established\r\n\r\n",
  );
  private static $ENTITY_HTTP_METHODS = array("POST" => null, "PUT" => null);
  private static $HOP_BY_HOP = array(
    'connection' => true,
    'keep-alive' => true,
    'proxy-authenticate' => true,
    'proxy-authorization' => true,
    'te' => true,
    'trailers' => true,
    'transfer-encoding' => true,
    'upgrade' => true
  );


  /** @var Google_Client */
  protected $client;

  public function __construct(Google_Client $client)
  {
    $this->client = $client;
    $timeout = $client->getClassConfig('Google_IO_Abstract', 'request_timeout_seconds');
    if ($timeout > 0) {
      $this->setTimeout($timeout);
    }
  }

  /**
   * Executes a Google_Http_Request
   * @param Google_Http_Request $request the http request to be executed
   * @return array containing response headers, body, and http code
   * @throws Google_IO_Exception on curl or IO error
   */
  abstract public function executeRequest(Google_Http_Request $request);

  /**
   * Set options that update the transport implementation's behavior.
   * @param $options
   */
  abstract public function setOptions($options);

  /**
   * Set the maximum request time in seconds.
   * @param $timeout in seconds
   */
  abstract public function setTimeout($timeout);

  /**
   * Get the maximum request time in seconds.
   * @return timeout in seconds
   */
  abstract public function getTimeout();

  /**
   * Test for the presence of a cURL header processing bug
   *
   * The cURL bug was present in versions prior to 7.30.0 and caused the header
   * length to be miscalculated when a "Connection established" header added by
   * some proxies was present.
   *
   * @return boolean
   */
  abstract protected function needsQuirk();

  /**
   * @visible for testing.
   * Cache the response to an HTTP request if it is cacheable.
   * @param Google_Http_Request $request
   * @return bool Returns true if the insertion was successful.
   * Otherwise, return false.
   */
  public function setCachedRequest(Google_Http_Request $request)
  {
    // Determine if the request is cacheable.
    if (Google_Http_CacheParser::isResponseCacheable($request)) {
      $this->client->getCache()->set($request->getCacheKey(), $request);
      return true;
    }

    return false;
  }

  /**
   * Execute an HTTP Request
   *
   * @param Google_HttpRequest $request the http request to be executed
   * @return Google_HttpRequest http request with the response http code,
   * response headers and response body filled in
   * @throws Google_IO_Exception on curl or IO error
   */
  public function makeRequest(Google_Http_Request $request)
  {
    // First, check to see if we have a valid cached version.
    $cached = $this->getCachedRequest($request);
    if ($cached !== false && $cached instanceof Google_Http_Request) {
      if (!$this->checkMustRevalidateCachedRequest($cached, $request)) {
        return $cached;
      }
    }

    if (array_key_exists($request->getRequestMethod(), self::$ENTITY_HTTP_METHODS)) {
      $request = $this->processEntityRequest($request);
    }

    list($responseData, $responseHeaders, $respHttpCode) = $this->executeRequest($request);

    if ($respHttpCode == 304 && $cached) {
      // If the server responded NOT_MODIFIED, return the cached request.
      $this->updateCachedRequest($cached, $responseHeaders);
      return $cached;
    }

    if (!isset($responseHeaders['Date']) && !isset($responseHeaders['date'])) {
      $responseHeaders['date'] = date("r");
    }

    $request->setResponseHttpCode($respHttpCode);
    $request->setResponseHeaders($responseHeaders);
    $request->setResponseBody($responseData);
    // Store the request in cache (the function checks to see if the request
    // can actually be cached)
    $this->setCachedRequest($request);
    return $request;
  }

  /**
   * @visible for testing.
   * @param Google_Http_Request $request
   * @return Google_Http_Request|bool Returns the cached object or
   * false if the operation was unsuccessful.
   */
  public function getCachedRequest(Google_Http_Request $request)
  {
    if (false === Google_Http_CacheParser::isRequestCacheable($request)) {
      return false;
    }

    return $this->client->getCache()->get($request->getCacheKey());
  }

  /**
   * @visible for testing
   * Process an http request that contains an enclosed entity.
   * @param Google_Http_Request $request
   * @return Google_Http_Request Processed request with the enclosed entity.
   */
  public function processEntityRequest(Google_Http_Request $request)
  {
    $postBody = $request->getPostBody();
    $contentType = $request->getRequestHeader("content-type");

    // Set the default content-type as application/x-www-form-urlencoded.
    if (false == $contentType) {
      $contentType = self::FORM_URLENCODED;
      $request->setRequestHeaders(array('content-type' => $contentType));
    }

    // Force the payload to match the content-type asserted in the header.
    if ($contentType == self::FORM_URLENCODED && is_array($postBody)) {
      $postBody = http_build_query($postBody, '', '&');
      $request->setPostBody($postBody);
    }

    // Make sure the content-length header is set.
    if (!$postBody || is_string($postBody)) {
      $postsLength = strlen($postBody);
      $request->setRequestHeaders(array('content-length' => $postsLength));
    }

    return $request;
  }

  /**
   * Check if an already cached request must be revalidated, and if so update
   * the request with the correct ETag headers.
   * @param Google_Http_Request $cached A previously cached response.
   * @param Google_Http_Request $request The outbound request.
   * return bool If the cached object needs to be revalidated, false if it is
   * still current and can be re-used.
   */
  protected function checkMustRevalidateCachedRequest($cached, $request)
  {
    if (Google_Http_CacheParser::mustRevalidate($cached)) {
      $addHeaders = array();
      if ($cached->getResponseHeader('etag')) {
        // [13.3.4] If an entity tag has been provided by the origin server,
        // we must use that entity tag in any cache-conditional request.
        $addHeaders['If-None-Match'] = $cached->getResponseHeader('etag');
      } elseif ($cached->getResponseHeader('date')) {
        $addHeaders['If-Modified-Since'] = $cached->getResponseHeader('date');
      }

      $request->setRequestHeaders($addHeaders);
      return true;
    } else {
      return false;
    }
  }

  /**
   * Update a cached request, using the headers from the last response.
   * @param Google_HttpRequest $cached A previously cached response.
   * @param mixed Associative array of response headers from the last request.
   */
  protected function updateCachedRequest($cached, $responseHeaders)
  {
    $hopByHop = self::$HOP_BY_HOP;
    if (!empty($responseHeaders['connection'])) {
      $connectionHeaders = array_map(
          'strtolower',
          array_filter(
              array_map('trim', explode(',', $responseHeaders['connection']))
          )
      );
      $hopByHop += array_fill_keys($connectionHeaders, true);
    }

    $endToEnd = array_diff_key($responseHeaders, $hopByHop);
    $cached->setResponseHeaders($endToEnd);
  }

  /**
   * Used by the IO lib and also the batch processing.
   *
   * @param $respData
   * @param $headerSize
   * @return array
   */
  public function parseHttpResponse($respData, $headerSize)
  {
    // check proxy header
    foreach (self::$CONNECTION_ESTABLISHED_HEADERS as $established_header) {
      if (stripos($respData, $established_header) !== false) {
        // existed, remove it
        $respData = str_ireplace($established_header, '', $respData);
        // Subtract the proxy header size unless the cURL bug prior to 7.30.0
        // is present which prevented the proxy header size from being taken into
        // account.
        if (!$this->needsQuirk()) {
          $headerSize -= strlen($established_header);
        }
        break;
      }
    }

    if ($headerSize) {
      $responseBody = substr($respData, $headerSize);
      $responseHeaders = substr($respData, 0, $headerSize);
    } else {
      $responseSegments = explode("\r\n\r\n", $respData, 2);
      $responseHeaders = $responseSegments[0];
      $responseBody = isset($responseSegments[1]) ? $responseSegments[1] :
                                                    null;
    }

    $responseHeaders = $this->getHttpResponseHeaders($responseHeaders);
    return array($responseHeaders, $responseBody);
  }

  /**
   * Parse out headers from raw headers
   * @param rawHeaders array or string
   * @return array
   */
  public function getHttpResponseHeaders($rawHeaders)
  {
    if (is_array($rawHeaders)) {
      return $this->parseArrayHeaders($rawHeaders);
    } else {
      return $this->parseStringHeaders($rawHeaders);
    }
  }

  private function parseStringHeaders($rawHeaders)
  {
    $headers = array();
    $responseHeaderLines = explode("\r\n", $rawHeaders);
    foreach ($responseHeaderLines as $headerLine) {
      if ($headerLine && strpos($headerLine, ':') !== false) {
        list($header, $value) = explode(': ', $headerLine, 2);
        $header = strtolower($header);
        if (isset($headers[$header])) {
          $headers[$header] .= "\n" . $value;
        } else {
          $headers[$header] = $value;
        }
      }
    }
    return $headers;
  }

  private function parseArrayHeaders($rawHeaders)
  {
    $header_count = count($rawHeaders);
    $headers = array();

    for ($i = 0; $i < $header_count; $i++) {
      $header = $rawHeaders[$i];
      // Times will have colons in - so we just want the first match.
      $header_parts = explode(': ', $header, 2);
      if (count($header_parts) == 2) {
        $headers[strtolower($header_parts[0])] = $header_parts[1];
      }
    }

    return $headers;
  }
}
 
/*
 * Copyright 2014 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Curl based implementation of Google_IO.
 *
 * @author Stuart Langley <slangley@google.com>
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_IO_Curl extends Google_IO_Abstract
{
  // cURL hex representation of version 7.30.0
  const NO_QUIRK_VERSION = 0x071E00;

  private $options = array();

  public function __construct(Google_Client $client)
  {
    if (!extension_loaded('curl')) {
      $error = 'The cURL IO handler requires the cURL extension to be enabled';
      $client->getLogger()->critical($error);
      throw new Google_IO_Exception($error);
    }

    parent::__construct($client);
  }

  /**
   * Execute an HTTP Request
   *
   * @param Google_Http_Request $request the http request to be executed
   * @return array containing response headers, body, and http code
   * @throws Google_IO_Exception on curl or IO error
   */
  public function executeRequest(Google_Http_Request $request)
  {
    $curl = curl_init();

    if ($request->getPostBody()) {
      curl_setopt($curl, CURLOPT_POSTFIELDS, $request->getPostBody());
    }

    $requestHeaders = $request->getRequestHeaders();
    if ($requestHeaders && is_array($requestHeaders)) {
      $curlHeaders = array();
      foreach ($requestHeaders as $k => $v) {
        $curlHeaders[] = "$k: $v";
      }
      curl_setopt($curl, CURLOPT_HTTPHEADER, $curlHeaders);
    }
    curl_setopt($curl, CURLOPT_URL, $request->getUrl());

    curl_setopt($curl, CURLOPT_CUSTOMREQUEST, $request->getRequestMethod());
    curl_setopt($curl, CURLOPT_USERAGENT, $request->getUserAgent());

    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
    // 1 is CURL_SSLVERSION_TLSv1, which is not always defined in PHP.
    curl_setopt($curl, CURLOPT_SSLVERSION, 1);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HEADER, true);

    if ($request->canGzip()) {
      curl_setopt($curl, CURLOPT_ENCODING, 'gzip,deflate');
    }
    
    $options = $this->client->getClassConfig('Google_IO_Curl', 'options');
    if (is_array($options)) {
      $this->setOptions($options);
    }
    
    foreach ($this->options as $key => $var) {
      curl_setopt($curl, $key, $var);
    }

    if (!isset($this->options[CURLOPT_CAINFO])) {
      curl_setopt($curl, CURLOPT_CAINFO, dirname(__FILE__) . '/cacerts.pem');
    }

    $this->client->getLogger()->debug(
        'cURL request',
        array(
            'url' => $request->getUrl(),
            'method' => $request->getRequestMethod(),
            'headers' => $requestHeaders,
            'body' => $request->getPostBody()
        )
    );

    $response = curl_exec($curl);
    if ($response === false) {
      $error = curl_error($curl);
      $code = curl_errno($curl);
      $map = $this->client->getClassConfig('Google_IO_Exception', 'retry_map');

      $this->client->getLogger()->error('cURL ' . $error);
      throw new Google_IO_Exception($error, $code, null, $map);
    }
    $headerSize = curl_getinfo($curl, CURLINFO_HEADER_SIZE);

    list($responseHeaders, $responseBody) = $this->parseHttpResponse($response, $headerSize);
    $responseCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    $this->client->getLogger()->debug(
        'cURL response',
        array(
            'code' => $responseCode,
            'headers' => $responseHeaders,
            'body' => $responseBody,
        )
    );

    return array($responseBody, $responseHeaders, $responseCode);
  }

  /**
   * Set options that update the transport implementation's behavior.
   * @param $options
   */
  public function setOptions($options)
  {
    $this->options = $options + $this->options;
  }

  /**
   * Set the maximum request time in seconds.
   * @param $timeout in seconds
   */
  public function setTimeout($timeout)
  {
    // Since this timeout is really for putting a bound on the time
    // we'll set them both to the same. If you need to specify a longer
    // CURLOPT_TIMEOUT, or a tigher CONNECTTIMEOUT, the best thing to
    // do is use the setOptions method for the values individually.
    $this->options[CURLOPT_CONNECTTIMEOUT] = $timeout;
    $this->options[CURLOPT_TIMEOUT] = $timeout;
  }

  /**
   * Get the maximum request time in seconds.
   * @return timeout in seconds
   */
  public function getTimeout()
  {
    return $this->options[CURLOPT_TIMEOUT];
  }

  /**
   * Test for the presence of a cURL header processing bug
   *
   * {@inheritDoc}
   *
   * @return boolean
   */
  protected function needsQuirk()
  {
    $ver = curl_version();
    $versionNum = $ver['version_number'];
    return $versionNum < Google_IO_Curl::NO_QUIRK_VERSION;
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_IO_Exception extends Google_Exception implements Google_Task_Retryable
{
  /**
   * @var array $retryMap Map of errors with retry counts.
   */
  private $retryMap = array();

  /**
   * Creates a new IO exception with an optional retry map.
   *
   * @param string $message
   * @param int $code
   * @param Exception|null $previous
   * @param array|null $retryMap Map of errors with retry counts.
   */
  public function __construct(
      $message,
      $code = 0,
      Exception $previous = null,
      array $retryMap = null
  ) {
    if (version_compare(PHP_VERSION, '5.3.0') >= 0) {
      parent::__construct($message, $code, $previous);
    } else {
      parent::__construct($message, $code);
    }

    if (is_array($retryMap)) {
      $this->retryMap = $retryMap;
    }
  }

  /**
   * Gets the number of times the associated task can be retried.
   *
   * NOTE: -1 is returned if the task can be retried indefinitely
   *
   * @return integer
   */
  public function allowedRetries()
  {
    if (isset($this->retryMap[$this->code])) {
      return $this->retryMap[$this->code];
    }

    return 0;
  }
}
 
/*
 * Copyright 2013 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Http Streams based implementation of Google_IO.
 *
 * @author Stuart Langley <slangley@google.com>
 */

if (!class_exists('Google_Client')) {
  require_once dirname(__FILE__) . '/../autoload.php';
}

class Google_IO_Stream extends Google_IO_Abstract
{
  const TIMEOUT = "timeout";
  const ZLIB = "compress.zlib://";
  private $options = array();
  private $trappedErrorNumber;
  private $trappedErrorString;

  private static $DEFAULT_HTTP_CONTEXT = array(
    "follow_location" => 0,
    "ignore_errors" => 1,
  );

  private static $DEFAULT_SSL_CONTEXT = array(
    "verify_peer" => true,
  );

  public function __construct(Google_Client $client)
  {
    if (!ini_get('allow_url_fopen')) {
      $error = 'The stream IO handler requires the allow_url_fopen runtime ' .
               'configuration to be enabled';
      $client->getLogger()->critical($error);
      throw new Google_IO_Exception($error);
    }

    parent::__construct($client);
  }

  /**
   * Execute an HTTP Request
   *
   * @param Google_Http_Request $request the http request to be executed
   * @return array containing response headers, body, and http code
   * @throws Google_IO_Exception on curl or IO error
   */
  public function executeRequest(Google_Http_Request $request)
  {
    $default_options = stream_context_get_options(stream_context_get_default());

    $requestHttpContext = array_key_exists('http', $default_options) ?
        $default_options['http'] : array();

    if ($request->getPostBody()) {
      $requestHttpContext["content"] = $request->getPostBody();
    }

    $requestHeaders = $request->getRequestHeaders();
    if ($requestHeaders && is_array($requestHeaders)) {
      $headers = "";
      foreach ($requestHeaders as $k => $v) {
        $headers .= "$k: $v\r\n"; 
      }
      $requestHttpContext["header"] = $headers;
    }

    $requestHttpContext["method"] = $request->getRequestMethod();
    $requestHttpContext["user_agent"] = $request->getUserAgent();

    $requestSslContext = array_key_exists('ssl', $default_options) ?
        $default_options['ssl'] : array();

    if (!array_key_exists("cafile", $requestSslContext)) {
      $requestSslContext["cafile"] = dirname(__FILE__) . '/cacerts.pem';
    }

    $options = array(
        "http" => array_merge(
            self::$DEFAULT_HTTP_CONTEXT,
            $requestHttpContext
        ),
        "ssl" => array_merge(
            self::$DEFAULT_SSL_CONTEXT,
            $requestSslContext
        )
    );

    $context = stream_context_create($options);

    $url = $request->getUrl();

    if ($request->canGzip()) {
      $url = self::ZLIB . $url;
    }

    $this->client->getLogger()->debug(
        'Stream request',
        array(
            'url' => $url,
            'method' => $request->getRequestMethod(),
            'headers' => $requestHeaders,
            'body' => $request->getPostBody()
        )
    );

    // We are trapping any thrown errors in this method only and
    // throwing an exception.
    $this->trappedErrorNumber = null;
    $this->trappedErrorString = null;

    // START - error trap.
    set_error_handler(array($this, 'trapError'));
    $fh = fopen($url, 'r', false, $context);
    restore_error_handler();
    // END - error trap.

    if ($this->trappedErrorNumber) {
      $error = sprintf(
          "HTTP Error: Unable to connect: '%s'",
          $this->trappedErrorString
      );

      $this->client->getLogger()->error('Stream ' . $error);
      throw new Google_IO_Exception($error, $this->trappedErrorNumber);
    }

    $response_data = false;
    $respHttpCode = self::UNKNOWN_CODE;
    if ($fh) {
      if (isset($this->options[self::TIMEOUT])) {
        stream_set_timeout($fh, $this->options[self::TIMEOUT]);
      }

      $response_data = stream_get_contents($fh);
      fclose($fh);

      $respHttpCode = $this->getHttpResponseCode($http_response_header);
    }

    if (false === $response_data) {
      $error = sprintf(
          "HTTP Error: Unable to connect: '%s'",
          $respHttpCode
      );

      $this->client->getLogger()->error('Stream ' . $error);
      throw new Google_IO_Exception($error, $respHttpCode);
    }

    $responseHeaders = $this->getHttpResponseHeaders($http_response_header);

    $this->client->getLogger()->debug(
        'Stream response',
        array(
            'code' => $respHttpCode,
            'headers' => $responseHeaders,
            'body' => $response_data,
        )
    );

    return array($response_data, $responseHeaders, $respHttpCode);
  }

  /**
   * Set options that update the transport implementation's behavior.
   * @param $options
   */
  public function setOptions($options)
  {
    $this->options = $options + $this->options;
  }

  /**
   * Method to handle errors, used for error handling around
   * stream connection methods.
   */
  public function trapError($errno, $errstr)
  {
    $this->trappedErrorNumber = $errno;
    $this->trappedErrorString = $errstr;
  }

  /**
   * Set the maximum request time in seconds.
   * @param $timeout in seconds
   */
  public function setTimeout($timeout)
  {
    $this->options[self::TIMEOUT] = $timeout;
  }

  /**
   * Get the maximum request time in seconds.
   * @return timeout in seconds
   */
  public function getTimeout()
  {
    return $this->options[self::TIMEOUT];
  }

  /**
   * Test for the presence of a cURL header processing bug
   *
   * {@inheritDoc}
   *
   * @return boolean
   */
  protected function needsQuirk()
  {
    return false;
  }

  protected function getHttpResponseCode($response_headers)
  {
    $header_count = count($response_headers);

    for ($i = 0; $i < $header_count; $i++) {
      $header = $response_headers[$i];
      if (strncasecmp("HTTP", $header, strlen("HTTP")) == 0) {
        $response = explode(' ', $header);
        return $response[1];
      }
    }
    return self::UNKNOWN_CODE;
  }
}
