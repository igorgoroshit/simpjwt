<?php

namespace Igorgoroshit\JWT\Helpers;

class Base64 {

  public static function encode($input, $urlSafe = true) {

    if(!$urlSafe) {
      return base64_encode($input);
    }

    return self::urlsafeB64Encode($input);

  }


  public static function decode($input, $urlSafe = true) {
    
    if(!$urlSafe) {
      return base64_decode($input);
    }

    return self::urlsafeB64Decode($input);

  }


  protected static function urlsafeB64Decode($input) {

    $remainder = strlen($input) % 4;

    if ( $remainder ) {
      $padlen = 4 - $remainder;
      $input .= str_repeat('=', $padlen);
    }

    return base64_decode(
      strtr($input, '-_', '+/')
    );

  }


  protected static function urlsafeB64Encode($input) {

    return str_replace('=', '', 
      strtr(
        base64_encode($input), '+/', '-_'
      )
    );
    
  }


}