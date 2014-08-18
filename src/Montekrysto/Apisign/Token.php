<?php  namespace Montekrysto\Apisign;

class Token {

	/**
	 * The key
	 * @var string
	 */
	protected $key;


	/**
	 * The secret key
	 * @var string
	 */
	protected $secret;

	/**
	 * Create a new token
	 * @param string $key
	 * @param string $secret
	 */
	function __construct($key, $secret)
	{
		$this->key = $key;
		$this->secret = $secret;
	}


	/**
	 * Get the key
	 * @return string
	 */
	public function getKey()
	{
	    return $this->key;
	}


	/**
	 * Get the secret key
	 * @return string
	 */
	public function getSecret()
	{
	    return $this->secret;
	}


} 