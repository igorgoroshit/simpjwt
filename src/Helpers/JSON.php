<?php

namespace Igorgoroshit\SimpJWT\Helpers;

use DomainException;

class JSON {

  public static function decode($input) {   

    $obj = json_decode($input, false, 512, JSON_BIGINT_AS_STRING);
    
    if ( json_last_error() ) {
      throw new DomainException( json_last_error_msg() );
    } 
    
    if ( $obj === null && $input !== 'null' ) {
      throw new DomainException('Null result with non-null input');
    }

    return $obj;

  }


  public static function encode($input) {

    $json = json_encode($input);
    
    if ( json_last_error() ) {
      throw new DomainException( json_last_error_msg() );
    } 

    if ( $json === 'null' && $input !== null ) {
      throw new DomainException('Null result with non-null input');
    }

    return $json;

  }


}