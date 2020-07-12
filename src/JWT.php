<?php

namespace Igorgoroshit\SimpJWT;

use Igorgoroshit\SimpJWT\Helpers\ASN1;
use Igorgoroshit\SimpJWT\Helpers\JSON;
use Igorgoroshit\SimpJWT\Helpers\Base64;

use Igorgoroshit\SimpJWT\Exceptions\SignatureInvalidException;
use Igorgoroshit\SimpJWT\Exceptions\BeforeValidException;
use Igorgoroshit\SimpJWT\Exceptions\ExpiredException;

use UnexpectedValueException;
use DomainException;

class JWT {

    public static $leeway = 60;

    /**
     * List of supported hashing algorithms
     *
     * @var array
     */
    protected $supported_algs = [
        'HS256' => ['hash_hmac', 'SHA256', 256],
        'HS384' => ['hash_hmac', 'SHA384', 384],
        'HS512' => ['hash_hmac', 'SHA512', 512],
        'RS256' => ['openssl',   'SHA256', 256],
        'RS384' => ['openssl',   'SHA384', 384],
        'RS512' => ['openssl',   'SHA512', 512],
        'ES256' => ['ecdsa',     'SHA256', 256],
        'ES384' => ['ecdsa',     'SHA384', 384],
        'ES512' => ['ecdsa',     'SHA512', 512],
    ];

    public function __construct()
    {

    }

    /**
     * Decodes a JWT string into a PHP object.
     *
     * @param string      $jwt           The JWT
     * @param string|Array|null $key     The secret key, or map of keys
     * @param Array       $allowed_algs  List of supported verification algorithms
     *
     * @return object      The JWT's payload as a PHP object
     */
    public function decode($jwt, $key = null, array $allowed_algs = [])
    {
      $now    = time();
      $nowMin = $now - self::$leeway;
      $nowMax = $now + self::$leeway;

      $tks = explode('.', $jwt);

      if (count($tks) != 3) {
        throw new UnexpectedValueException('Invalid number of segments');
      }

      list($headb64, $bodyb64, $cryptob64) = $tks;

      $header = JSON::decode(
        Base64::decode($headb64)
      );
      
      if ( $header === null ) {
        throw new UnexpectedValueException('Invalid header encoding');
      }

      $payload = JSON::decode(
        Base64::decode($bodyb64)
      );

      if ( $payload === null ) {
        throw new UnexpectedValueException('Invalid claims encoding');
      }

      $sig = Base64::decode($cryptob64);

      if ( $sig === null ) {
        throw new UnexpectedValueException('Invalid signature encoding');
      }

      if ( empty($header->alg) ) {
        throw new DomainException('Empty algorithm');
      }

      if ( empty($this->supported_algs[$header->alg]) ) {
        throw new DomainException('Algorithm not supported');
      }

      if ( !in_array($header->alg, $allowed_algs) ) {
        throw new DomainException('Algorithm not allowed');
      }

      if( is_array($key) && empty($header->kid) ) {
        throw new DomainException('"kid" empty, unable to lookup correct key');
      }

      if( is_array($key) && isset($header->kid) && !isset($key[$header->kid]) ) {
        throw new DomainException('"kid" not found, unable to lookup correct key');
      }

      if( is_array($key) && isset($header->kid) && isset($key[$header->kid]) ) {
        $key = $key[$header->kid];
      }

      if( empty($key) ) {
        throw new DomainException('Empty key');
      }
      

      // Check the signature
      if ( !$this->verify("$headb64.$bodyb64", $sig, $key, $header->alg) ) {
        throw new SignatureInvalidException('Signature verification failed');
      }

      // Check if the nbf if it is defined. This is the time that the
      // token can actually be used. If it's not yet that time, abort.
      if ( isset($payload->nbf) && $payload->nbf > $nowMax ) {
        throw new BeforeValidException(
            'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->nbf)
        );
      }

      // Check that this token has been created before 'now'. This prevents
      // using tokens that have been created for later use (and haven't
      // correctly used the nbf claim).
      if ( isset($payload->iat) && $payload->iat > $nowMax ) {
        throw new BeforeValidException(
            'Cannot handle token prior to ' . date(\DateTime::ISO8601, $payload->iat)
        );
      }

      if ( isset($payload->exp) && $payload->exp < $nowMin )  {
        throw new ExpiredException(
          'Token expired at '  . date(\DateTime::ISO8601, $payload->exp)
        );
      }

      return $payload;
    }


    /**
     * Converts and signs a PHP object or array into a JWT string.
     *
     * @param object|array $payload PHP object or array
     * @param string       $key     The secret key
     * @param string       $alg     The signing algorithm. Supported
     *
     * @return string      A signed JWT
     */
    public function encode($payload, $key, $alg = 'HS256', $keyId = null)
    {
      $header = [
        'typ' => 'JWT',
        'alg' => $alg,
      ];

      if ( $keyId !== null ) {
          $header['kid'] = $keyId;
      }

      $segments = [];
      
      $segments[] = Base64::encode(
          JSON::encode($header)
      );

      $segments[] = Base64::encode(
          JSON::encode($payload)
      );

      $signing_input  = implode('.', $segments);
      $signature      = $this->sign($signing_input, $key, $alg);
      $segments[]     = Base64::encode($signature);

      return implode('.', $segments);
    }

    /**
     * Sign a string with a given key and algorithm.
     *
     * @param string $msg          The message to sign
     * @param string|resource $key The secret key
     * @param string $alg       The signing algorithm. Supported algorithms
     *
     * @return string          An encrypted message
     */
    private function sign($msg, $key, $alg = 'HS256')
    {
      if (empty($this->supported_algs[$alg])) 
      {
          throw new DomainException('Algorithm not supported');
      }

      list($function, $algorithm, $size) = $this->supported_algs[$alg];
       
      $signature = '';

      switch($function) 
      {
        case 'openssl':

          $success = openssl_sign($msg, $signature, $key, $algorithm);
          if (!$success) {
              throw new DomainException("OpenSSL unable to sign data");
          }

          return $signature;

        case 'ecdsa':

          $success = openssl_sign($msg, $signature, $key, $algorithm);
          if (!$success) {
              throw new DomainException("OpenSSL unable to sign data");
          }

          return ASN1::fromDER($signature, $size);

        case 'hash_hmac':
          return hash_hmac($algorithm, $msg, $key, true);

        default:

      }
    }

    /**
     * Verify a signature with the mesage, key and method. Not all methods
     * are symmetric, so we must have a separate verify and sign method.
     *
     * @param string $msg the original message
     * @param string $signature
     * @param string|resource $key for HS*, a string key works. for RS*, must be a resource of an openssl public key
     * @param string $alg
     * @return bool
     */
    private function verify($msg, $signature, $key, $alg)
    {
      if (empty($this->supported_algs[$alg])) {
        throw new DomainException('Algorithm not supported');
      }

      list($function, $algorithm, $size) = $this->supported_algs[$alg];

      switch($function) 
      {
        case 'openssl':
        case 'ecdsa':

          $success = openssl_verify($msg, $signature, $key, $algorithm);
          if ($success === -1) {
              throw new DomainException("OpenSSL unable to verify data: " . openssl_error_string());
          }

          return $success == 1;

        case 'hash_hmac':
          
          $hash = hash_hmac($algorithm, $msg, $key, true);

          return hash_equals($signature, $hash);

        default:

      }
    }
}