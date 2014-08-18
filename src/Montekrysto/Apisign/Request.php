<?php  namespace Montekrysto\Apisign;

use Montekrsto\Apisign\Exception\AuthenticationException;

class Request {

	/**
	 * The HTTP method of the request (GET, POST, etc...)
	 * @var string
	 */
	protected $method;

	/**
	 * The API endpoint
	 * @var string
	 */
	protected $path;

	/**
	 * The data to send
	 * @var array
	 */
	protected $params;

	/**
	 * The version of Signature
	 * @var string
	 */
	protected $version = '1.0';

	/**
	 * The default auth parameters
	 * @var array
	 */
	protected $auth_params = array(
		'auth_version'	=> null,
		'auth_key'		=> null,
		'auth_timestamp'=> null,
		'auth_signature'=> null
	);

	/**
	 * The query params
	 * @var array
	 */
	protected $query_params = array();

	function __construct($method, $path, array $params)
	{
		$this->method = strtoupper($method);

		$this->path = $path;

		// Separate the params into auth_params and query_params
		foreach($params as $key => $val)
		{
			$key = strtolower($key);
			if (substr($key, 0, 5) == 'auth_') // check if this is an auth_param
			{
				$this->auth_params[$key] = $val;
			} else
			{
				$this->query_params[$key] = $val;
			}
		}
	}


	/**
	 * Sign the request with a token
	 * @param Token $token
	 * @return array
	 */
	public function signRequest(Token $token)
	{
		// Set default parameters
		$this->auth_params = array(
			'auth_version'	=> '1.0',
			'auth_key'		=> $token->getKey(),
			'auth_timestamp'=> time()
		);

		$this->auth_params['auth_signature'] = $this->signature($token);

		return $this->auth_params;
	}


	/**
	 * Return a hashed signature
	 * @param Token $token
	 * @return string a hash of the request
	 */
	protected function signature(Token $token)
	{
		return hash_hmac('sha256', $token->getSecret(), $this->stringToSign());
	}


	/**
	 * String to sign
	 * @return string
	 */
	protected function stringToSign()
	{
		return implode("\n", array($this->method, $this->path, $this->parameterString()));
	}


	/**
	 * Build parameter string
	 * @return string - a URL encoded query string
	 */
	protected function parameterString()
	{
		// Create an array to build the http query
		$array = array();

		// Merge the auth_params and query_params
		$params = array_merge($this->auth_params, $this->query_params);

		// Convert keys to lowercase
		foreach($params as $key => $val)
		{
			$array[strtolower($key)] = $val;
		}

		// Remove the signature key
		unset($array['auth_signature']);

		// Encode array to http string
		return http_build_query($array);
	}


	/**
	 * Authenticate a request - ensure the auth_key and the token are the same
	 * @param Token $token
	 * @param int $timestampGrace
	 * @return mixed
	 * @throws Exception\AuthenticationException
	 */
	public function authenticate(Token $token, $timestampGrace = 600)
	{
		// Check to see if the authentication key is correct
//		if($this->auth_params['auth_key'] == $token->getKey())
		if(strcmp($this->auth_params['auth_key'], $token->getKey()) == 0)
		{
			return $this->authenticateByToken($token, $timestampGrace);
		}

		echo 'auth_params[auth_key] = ' . $this->auth_params['auth_key'];
		echo '   getKey() = ' . $token->getKey();
		// Error!
		throw new AuthenticationException('The auth_key is incorrect');
	}


	protected function authenticateByToken(Token $token, $timestampGrace)
	{
		// Check token
		if($token->getSecret() == null)
		{
			throw new AuthenticationException('The token secret is not set');
		}

		// Make sure we are using the same version
		$this->validateVersion();

		// Validate timestamp
		$this->validateTimestamp($timestampGrace);

		// Validate signature
		$this->validateSignature($token);

		return true;
	}


	/**
	 * Check the version
	 * @return bool
	 * @throws Exception\AuthenticationException
	 */
	protected function validateVersion()
	{

		if(strcmp($this->auth_params['auth_version'], $this->version) !== 0)
		{
			throw new AuthenticationException('The auth_version is incorrect');
		}

		return true;
	}


	/**
	 * Validate the timestamp
	 * @param $timestampGrace
	 * @return bool
	 * @throws Exception\AuthenticationException
	 */
	protected function validateTimeStamp($timestampGrace)
	{
		if($timestampGrace == 0) return true;

		$difference = $this->auth_params['auth_timestamp'] - time();

		// Is difference greater than the grace time period?
		if($difference >= $timestampGrace)
		{
			throw new AuthenticationException('The auth_timestamp is invalid');
		}

		return true;
	}


	/**
	 * Check the signature
	 * @param Token $token
	 * @return bool
	 * @throws Exception\AuthenticationException
	 */
	protected function validateSignature(Token $token)
	{
//		var_dump($this->signature($token));
//		var_dump($this->auth_params);dd();
		//if($this->auth_params !== $this->signature($token))
		if(strcmp($this->auth_params['auth_signature'], $this->signature($token)) !== 0)
		{
			throw new AuthenticationException('The auth_signature is incorrect');
		}

		return true;
	}

}