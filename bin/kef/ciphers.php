<?php
namespace tpkarras\KEF;

class CipherTools {

public static function convertCipher($cipher){

if(!is_string($cipher) && !is_array($cipher)){
Settings::throwException(4, 9, "Parameter \"\$cipher\" is required to be of type \"string/array\"");
}

$cipher_methods = ["aes", "aria", "camellia", "chacha20", "des", "des3", "sm4"];

$cipher_options = [["string" => "128", "compatible" => [0, 1, 2]],
["string" => "192", "compatible" => [0, 1, 2]],
["string" => "256", "compatible" => [0, 1, 2]],
["string" => "cbc", "compatible" => [0, 1, 2, 4, 6]],
["string" => "ccm", "compatible" => [0, 1]],
["string" => "cfb", "compatible" => [0, 1, 2, 4, 6]],
["string" => "cfb1", "compatible" => [0, 1, 2, 4]],
["string" => "cfb8", "compatible" => [0, 1, 2, 4]],
["string" => "ctr", "compatible" => [0, 1, 2, 6]],
["string" => "cts", "compatible" => [0, 2]],
["string" => "ecb", "compatible" => [0, 1, 2, 4, 6]],
["string" => "ede", "compatible" => [4]],
["string" => "ede3", "compatible" => [4]],
["string" => "gcm", "compatible" => [0, 1]],
["string" => "inv", "compatible" => [0]],
["string" => "ocb", "compatible" => [0]],
["string" => "ofb", "compatible" => [0, 1, 2, 4, 6]],
["string" => "pad", "compatible" => [0]],
["string" => "poly1305", "compatible" => [3]],
["string" => "siv", "compatible" => [0]],
["string" => "wrap", "compatible" => [0, 4, 5]],
["string" => "xts", "compatible" => [0]]];

if(empty($cipher)){
Settings::throwException(4, 4);
}

if(is_string($cipher)){

if(array_search($cipher, openssl_get_cipher_methods()) === false){
Settings::throwException(4, 5);
}

$cipher = explode("-", $cipher);

foreach($cipher as $k => $v){

if($k === 0){

$v = array_search($v, $cipher_methods);

if($v === false){
Settings::throwException(4, 5);
}

$cipher[$k] = $v;

} else {

foreach($cipher_options as $k2 => $v2){

if($v2["string"] === $v){

if(array_search(reset($cipher), $v2["compatible"]) === false){
Settings::throwException(4, 5);
}

$cipher[$k] = $k2;
break;
}

}

}

}

return $cipher;

} else {

foreach($cipher as $k => $v){

if(!is_int($v)){

Settings::throwException(4, 9);

}

if($k === 0){

if(!isset($cipher_methods[$v])){

Settings::throwException(4, 5);

}

$method = $v;
$cipher[$k] = $cipher_methods[$v];

} else {

if(!isset($cipher_options[$v])){

Settings::throwException(4, 5);

}

if(array_search($method, $cipher_options[$v]["compatible"]) === false){

Settings::throwException(4, 0);

}

$cipher[$k] = $cipher_options[$v]["string"];

}

}

$cipher = implode("-", $cipher);

if(array_search($cipher, openssl_get_cipher_methods()) === false){

Settings::throwException(4, 5);

}

return $cipher;

}

}

public static function supportsIV($cipher){

if(!is_string($cipher) && !is_array($cipher)){
	
Settings::throwException(4, 9, "Parameter \"\$cipher\" is required to be of type \"string/array\"");

}

if(empty($cipher)){
	
Settings::throwException(4, 4);

}

if(is_array($cipher)){
	
$cipher = self::cipherConvert($cipher);

}

if(array_search($cipher, openssl_get_cipher_methods()) === false){
	
Settings::throwException(4, 5);

}

$iv = @openssl_cipher_iv_length($cipher);

if($iv === 0){
	
return false;

} else {
	
return $iv;

}

}

}
