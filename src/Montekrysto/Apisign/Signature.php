<?php  namespace Montekrysto\Apisign;

class Signature {

	/**
	 * 
	 * @param $key
	 * @param $secret
	 * @return Token
	 */
	public function token($key, $secret)
	{
	    return new Token($key, $secret);
	}


	/**
	 * @param $method
	 * @param $path
	 * @param array $params
	 * @return Request
	 */
	public function request($method, $path, array $params)
	{
	    return new Request($method, $path, $params);
	}

} 