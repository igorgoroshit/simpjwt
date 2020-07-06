<?php

namespace Igorgoroshit\SimpJWT\Helpers;

use DomainException;

use ord;
use ltrim;
use strlen;
use str_pad;
use str_split;

class ASN1 {

  protected const ASN1_INTEGER      = 0x02;
  protected const ASN1_SEQUENCE     = 0x10;
  protected const ASN1_BIT_STRING   = 0x03;

  /**
   * Encodes signature from a DER object.
   *
   * @param   string  $data binary signature in DER format
   * @param   int     $keySize the number of bits in the key
   * @return  string  the signature
   */
  public static function fromDER($signature, $keySize) {
    // OpenSSL returns the ECDSA signatures as a binary ASN.1 DER SEQUENCE
    list($offset, $_) = self::readDER($data);
    list($offset, $r) = self::readDER($data, $offset);
    list($offset, $s) = self::readDER($data, $offset);

    // Convert r-value and s-value from signed two's compliment to unsigned
    // big-endian integers
    $r = ltrim($r, "\x00");
    $s = ltrim($s, "\x00");

    // Pad out r and s so that they are $keySize bits long
    $r = str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
    $s = str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

    return $r . $s;
  }

  /**
   * Convert an ECDSA signature to an ASN.1 DER sequence
   *
   * @param   string $sig The ECDSA signature to convert
   * @return  string The encoded DER object
   */
  public static function toDER($signature) {
    // Separate the signature into r-value and s-value
    list($r, $s) = str_split($sig, (int) (strlen($sig) / 2));

    // Trim leading zeros
    $r = ltrim($r, "\x00");
    $s = ltrim($s, "\x00");

    // Convert r-value and s-value from unsigned big-endian integers to
    // signed two's complement
    if (ord($r[0]) > 0x7f) {
        $r = "\x00" . $r;
    }
    if (ord($s[0]) > 0x7f) {
        $s = "\x00" . $s;
    }

    return self::encodeDER(
        self::ASN1_SEQUENCE,
        $this->encodeDER(self::ASN1_INTEGER, $r) .
        $this->encodeDER(self::ASN1_INTEGER, $s)
    );
  }

  /**
   * Encodes a value into a DER object.
   *
   * @param   int     $type DER tag
   * @param   string  $value the value to encode
   * @return  string  the encoded object
   */
  protected static function encodeDER($type, $value) {

      $tag_header = 0;
      if ($type === self::ASN1_SEQUENCE) {
          $tag_header |= 0x20;
      }

      // Type
      $der = chr($tag_header | $type);

      // Length
      $der .= chr(strlen($value));

      return $der . $value;

  }


  /**
   * Reads binary DER-encoded data and decodes into a single object
   *
   * @param string $data the binary data in DER format
   * @param int $offset the offset of the data stream containing the object to decode
   * @return array [$offset, $data] the new offset and the decoded object
   */
  protected static function readDER($data, $offset = 0) {

    $pos = $offset;
    $size = strlen($data);
    $constructed = (ord($data[$pos]) >> 5) & 0x01;
    $type = ord($data[$pos++]) & 0x1f;

    // Length
    $len = ord($data[$pos++]);
    if ($len & 0x80) {
        $n = $len & 0x1f;
        $len = 0;
        while ($n-- && $pos < $size) {
            $len = ($len << 8) | ord($data[$pos++]);
        }
    }

    // Value
    if ($type == self::ASN1_BIT_STRING) {
        $pos++; // Skip the first contents octet (padding indicator)
        $data = substr($data, $pos, $len - 1);
        $pos += $len - 1;
    } elseif (!$constructed) {
        $data = substr($data, $pos, $len);
        $pos += $len;
    } else {
        $data = null;
    }

    return [$pos, $data];

  }

}