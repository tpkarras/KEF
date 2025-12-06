<?php
namespace tpkarras\KEF;

function encryptDataKEF(string $data, array $passphrase, string $cipher, int $byte_range = 0, int $multi_encrypt_split = 0, string|null $aad = null, string|null $output = null){

if(empty($data) || empty($passphrase) || empty($cipher) || $byte_range < 0 || $multi_encrypt_split < 0 || is_string($output) && empty($output)){
	
throw new KEFException(0, 4);

}

foreach($passphrase as $p){
	
if(!is_string($p)){
	
throw new KEFException(0, 9, "Passphrase in array is not a string");

}

if(empty($p)){

throw new KEFException(0, 9, "Passphrase cannot be empty");
	
}

}

if(!preg_match("/gcm$|ccm$/", $cipher)){

throw new KEFException(0, 0, "Cipher is not GCM/CCM");

}

if(is_string($aad) && empty($aad)){
	
throw new KEFException(0, 4);

}

if($byte_range != 0 && ($byte_range < Settings::MIN_BYTES || $byte_range > Settings::MAX_BYTES)){
	
throw new KEFException(0, 1);

}

if($byte_range == 0){

$byte_range = Settings::DEFAULT_BYTE_RANGE;

}

$cipher_octet = CipherTools::convertCipher($cipher);

if(!empty($output)){

if(strpos(strtolower(PHP_OS), "win") !== false){

$excluded_characters = "/[\<\>\\\:\|\?\*]|CON|PRN|AUX|NUL|COM1|COM2|COM3|COM4|COM5|COM6|COM7|COM8|COM9|LPT1|LPT2|LPT3|LPT4|LPT5|LPT6|LPT7|LPT8|LPT9/";

if(preg_match($excluded_characters, $output)){
	
throw new KEFException(0, 9, "Excluded characters found");

}

}

foreach(str_split($output) as $v){
	
if(convertCharacter($v) <= 31){
	
throw new KEFException(0, 9, "Excluded characters found");

}

}

if(strpos($output, "/") !== false && !is_dir(preg_replace("/\/[^\/]+$/", "", $output))){

throw new KEFException(0, 9, "Not a directory");

}

if(is_file($output)){
	
throw new KEFException(0, 11);

}

if(file_put_contents($output, "") === false){
	
throw new KEFException(0, 10);

}

$file = fopen($output, "wb");

$tmp_file = tmpfile();

}

if(is_file($data)){
	
$total_length = filesize($data);

$checksum = md5_file($data);

$data = fopen($data, "rb");

$content_type = mime_content_type($data);

} else {
	
$tmp = tmpfile();

fwrite($tmp, $data);

$content_type = mime_content_type($tmp);

fclose($tmp);

$total_length = strlen($data);

$checksum = md5($data);

$data = str_split($data, $byte_range);

}

$current_data = "";

if(is_null($aad)){
	
$aad = "";

}

$current_range = 0;

$octet_array = array(array());

$iv_l = CipherTools::supportsIV($cipher);

if(count($passphrase) > 1){
	
$multi_encrypt_split_current = 0;

if($multi_encrypt_split == 0){

$multi_encrypt_split = Settings::DEFAULT_BYTE_MULTI_ENCRYPT_SPLIT;

} 

if ($multi_encrypt_split > intval(floor(ceil($total_length / $byte_range) / count($passphrase)))){

throw new KEFException(0, 9, "Multi-encrypt split exceeds maximum number of ranges.");

}

}

$current_passphrase = reset($passphrase);

while($current_range < intval(ceil($total_length / $byte_range))){
	
if(!$iv_l){
	
$iv = null;

} else {
	
$iv = openssl_random_pseudo_bytes($iv_l);

}

$tag = null;

if(!is_array($data)){
	
$r = fread($data, $byte_range);

} else {
	
$r = $data[$current_range];

}
	
$row = openssl_encrypt($r, $cipher, $current_passphrase, OPENSSL_RAW_DATA, $iv, $tag, $aad);

if(is_bool($row) || is_null($row)){
	
throw new KEFException(2, 3);

}

$length = convertCharacter(strlen($row));

array_unshift($octet_array[0], strlen($length));

$row = $length.$row;

if(!is_null($iv)){
	
$length = convertCharacter(strlen($iv));

array_unshift($octet_array[0], strlen($length));

$row = $length.$iv.$row;

}

if(preg_match("/gcm|ccm/", $cipher)){
	
$length = convertCharacter(strlen($tag));

array_unshift($octet_array[0], strlen($length));

$row = $length.$tag.$row;

}

if(isset($tmp_file)){

if(!isset($buffer)){
	
$buffer = strlen($row);

} else {
	
$buffer = $buffer + strlen($row);

}

fwrite($tmp_file, $row);

} else {
	
$current_data .= $row;

}

unset($row);

$current_range++;

if(count($passphrase) > 1){

$multi_encrypt_split_current++;

if($multi_encrypt_split_current == $multi_encrypt_split){

$current_passphrase = next($passphrase);
$multi_encrypt_split_current = 0;

if($current_passphrase === false){
	
$current_passphrase = reset($passphrase);

}
	
}

}

}

$content_type = str_split($content_type, 1);

foreach($content_type as $k => $v){
	
$content_type[$k] = convertCharacter($v);

}

$checksum = str_split($checksum, 2);

foreach($checksum as $k => $v){
	
$checksum[$k] = hexdec($v);

}

array_unshift($octet_array, $cipher_octet, $total_length, $byte_range, $multi_encrypt_split, $content_type, $checksum);

$octets = "";
$current_octet = "";

foreach($octet_array as $element){

$length = 0;

if(is_array($element)){
	
$key = 0;

}

while(true){

if(!isset($number)){

if(isset($key)){
	
$number = $element[$key];

} else {
	
$number = $element;

}

}

if($number > 128){

if(is_string($length)){
	
$length .= hex2bin(dechex(255));

} else {
	
$current_octet .= hex2bin(dechex(255));

}

$number = $number - 128;

} else {

$number = dechex($number);

if(strlen($number) & 1){
	
$number = "0".$number;

}

if(is_string($length)){

$length .= hex2bin($number);

$current_octet = $length.$current_octet;

$length = null;

$octets .= $current_octet;

$current_octet = "";

unset($number);

break;

} else {
	
$current_octet .= hex2bin($number);

}

}

if(!is_string($length)){
	
$length++;

}

if(is_string($number)){

if(isset($key) && isset($element[$key + 1])){
	
$key++;

$number = $element[$key];

continue;

} else if($length > 0){
	
$number = $length;

$length = "";

continue;

}

}

}

unset($key);

}

if(isset($tmp_file)){
	
fwrite($file, $octets);

rewind($tmp_file);

fwrite($file, fread($tmp_file, $buffer));

fclose($tmp_file);

fclose($file);

return true;

} else {
	
$current_data = $octets.$current_data;

return $current_data;

}

}

function buffer(string $data, int $buffer_size = 0, int $level = 1, bool $return_info = false){

if(empty($data)){
	
throw new KEFException(2, 4);

}

if($buffer_size < 0 || $level < 1){
	
throw new KEFException(2, 9, "Parameter(s) less than 0/1");

}

if($buffer_size > 0 && $buffer_size < Settings::DEFAULT_BUFFER_SIZE){
	
throw new KEFException(2, 9, "Less than default buffer size");

}

if($buffer_size == 0){
	
$buffer_size = Settings::DEFAULT_BUFFER_SIZE;

}

if(is_string($data) && preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data))){
	
$response_code = null;

$checksum = null;

$total_length = null;

$ch = curl_init($data);

curl_setopt($ch, CURLOPT_HTTPHEADER, ["Range: bytes=".$buffer_size * ($level - 1)."-".$buffer_size * $level - 1]);

curl_setopt($ch, CURLOPT_USERAGENT, "tpkarras/KEF/1.5.0 (https://github.com/tpkarras)");

curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

curl_setopt($ch, CURLOPT_HEADERFUNCTION,

  function($curl, $header) use (&$response_code, &$checksum, &$total_length)
  {
  	
    $len = strlen($header);
    
    if(preg_match("/\d{3}/", $header, $response) && is_null($response_code)){
    	
    $response_code = intval($response[0]);
    unset($response);
    
    } else {
    	
    $header = explode(':', $header, 2);
    
    if(count($header) == 2){
    	
    if(strtolower($header[0]) == "content-length" && is_null($total_length)){
    	
$total_length = intval(trim($header[1]));
	}
	
    if(strtolower($header[0]) == "etag" && is_null($checksum)){
    	
$checksum = str_replace("\"", "", trim($header[1]));
  
  }
    
    }
    
    }
    
    return $len;
  }
  
);

$buffer = curl_exec($ch);

curl_close($ch);

if(array_search($response_code, [200, 206]) === false){
	
throw new KEFException(2, 12);

}

} else if(is_string($data) && is_file($data)){

$total_length = filesize($data);

$checksum = md5_file($data);

$data = fopen($data, "rb");

fseek($data, $buffer_size * ($level - 1));

$buffer = fread($data, $buffer_size);

if($buffer === false){
	
throw new KEFException(2, 12);

}

} else {
	
return false;

}

if(strlen($buffer) == 0){
	
throw new KEFException(2, 9, "Buffer is not supposed to be empty");

}

if($return_info){
	
$info = array();

$info[0] = $checksum;
$info[1] = $total_length;
$info[2] = $buffer;

return $info;

} else {
	
return $buffer;
}

}

class KEFInfo {

private $content_type = null;
private $content_length = null;
private $kef_length = null;
private $byte_range = null;
private $multi_encrypt_split = null;
private $size_array = array();
private $cipher = null;
private $checksum_original = null;
private $checksum_kef = null;
private $data_start = null;

public function getContentType(){
	
return $this->content_type;

}

public function getDecryptionInfo(){
	
if(empty($this->size_array) || is_null($this->byte_range) || is_null($this->multi_encrypt_split) || is_null($this->cipher) || is_null($this->data_start)){
	
return null;

}

$info = array();

$info[0] = $this->cipher;
$info[1] = $this->byte_range;
$info[2] = $this->multi_encrypt_split;
$info[3] = $this->size_array;
$info[4] = $this->data_start;

return $info;

}

public function getLength(bool $type = false){

if(!$type){
	
return $this->content_length;

} else {
	
return $this->kef_length;

}

}

public function getChecksum(bool $type = false){

if(!$type){
	
return $this->checksum_original;

} else {
	
return $this->checksum_kef;

}

}

private function clearData(){
	
if($this->cipher != null){
	
$this->cipher = null;

}

if($this->content_length != null){
	
$this->content_length = null;

}

if($this->kef_length != null){
	
$this->kef_length = null;

}

if($this->checksum_original != null){
	
$this->checksum_original = null;

}

if($this->checksum_kef != null){
	
$this->checksum_kef = null;

}

if($this->byte_range != null){
	
$this->byte_range = null;

}

if($this->multi_encrypt_split != null){
	
$this->byte_range = null;

}

if($this->content_type != null){
	
$this->content_type = null;

}

if(count($this->size_array) > 0){
	
$this->size_array = array();

}

}

private function importData(string|array $data){
	
if(preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data))){
	
$data = htmlentities($data);

$path = $data;

$data = buffer($path, 0, 1, true);

} else if(is_file($data)){
	
$path = $data;

$data = buffer($path, 0, 1, true);

}

if(is_array($data)){
	
$is_buffer = true;

$buffer_level = 1;

$buffer_size = Settings::DEFAULT_BUFFER_SIZE;

$this->checksum_kef = $data[0];

$this->kef_length = $data[1];

$data = $data[2];

} else {
	
$this->checksum_kef = md5($data);

$this->kef_length = strlen($data);

}

$current_position = 0;
$data_start = 0;
$octet_count = null;
$size_array_element = 0;
$content_type = "";
$checksum = "";
$cipher = [];

while(true){
	
$number = hexdec(bin2hex(substr($data, $current_position, 1)));

$current_position++;

if(isset($is_buffer) && $current_position == $buffer_size){
	
$data_start = $current_position + $data_start;

$buffer_level++;

$current_position = 0;

$data = buffer($path, 0, $buffer_level);

}

if($number == 255){
	
$size_array_element = $size_array_element + ($number >> 1) + 1;

} else if($number <= 128){
	
$size_array_element = $size_array_element + $number;

if(is_null($octet_count)){
	
$octet_count = $size_array_element;

$size_array_element = 0;

continue;

}

} else if ($number > 128){
	
$this->clearData();

throw new KEFException(2, 8);

}

if(!is_null($octet_count)){

if(is_null($this->cipher) && isset($cipher)){
	
array_push($cipher, $size_array_element);

$size_array_element = 0;

} else if(is_null($this->content_length) || is_null($this->byte_range) || is_null($this->multi_encrypt_split)){
	
$octet_count--;

} else if(is_null($this->content_type) || is_null($this->checksum_original)){
	
if(is_null($this->content_type)){
	
$content_type .= convertCharacter($size_array_element);

$size_array_element = 0;

} else if(is_null($this->checksum_original)){
	
$octet_count--;

if($number <= 128){
	
$hex = dechex($size_array_element);

if(strlen($hex) & 1){
	
$hex = "0".$hex;

}

$checksum .= $hex;

$size_array_element = 0;

}

}

} else {
	
array_push($this->size_array, $size_array_element);

$size_array_element = 0;

}

if(is_null($this->cipher) && count($cipher) == $octet_count){
	
try {

$this->cipher = CipherTools::convertCipher($cipher);

} catch (Exception $e){
	
$this->clearData();

throw $e;

}

unset($cipher);

$octet_count = null;

continue;

} else if(is_null($this->content_length) && $octet_count == 0){
	
$this->content_length = $size_array_element;
$size_array_element = 0;

$octet_count = null;

continue;

} else if(is_null($this->byte_range) && $octet_count == 0){
	
if($size_array_element < Settings::MIN_BYTES || $size_array_element > Settings::MAX_BYTES){
	
$this->clearData();

throw new KEFException(2, 1);

}

$this->byte_range = $size_array_element;

$size_array_element = 0;

$octet_count = null;

continue;

} else if(is_null($this->multi_encrypt_split) && $octet_count == 0){
	
$this->multi_encrypt_split = $size_array_element;

$size_array_element = 0;

$octet_count = null;

} else if(is_null($this->content_type) && strlen($content_type) == $octet_count){
	
$this->content_type = $content_type;

unset($content_type);

$octet_count = null;

continue;

} else if(is_null($this->checksum_original) && $octet_count == 0){
	
$this->checksum_original = $checksum;
unset($checksum);

$octet_count = null;

continue;

} else if(count($this->size_array) == $octet_count){

break;

}

}

}

if($current_position > 0){
	
$data_start = $current_position + $data_start;

}

unset($current_position);

$this->data_start = $data_start;

}

public function __construct(string $data){
	
if(!is_string($data)){
	
throw new KEFException(0, 9, "Parameter \"\$data\" is required to be of type \"string\"");

}

if(empty($data)){
	
throw new KEFException(0, 4);

}

$this->importData($data);

}

}

function decryptKEFData(KEFInfo $info, string $data, array $passphrase, string|null $aad = null, int $start = 0, int $end = 0, int $buffer_size = 0){

if(is_null($info->getContentType()) || is_null($info->getDecryptionInfo()) || is_null($info->getLength()) || is_null($info->getChecksum())){
	
throw new KEFException(1, 7, "KEFInfo is invalid");

}

if(empty($data)){
	
throw new KEFException(1, 4);

}

if(empty($passphrase)){
	
throw new KEFException(1, 4);

}

foreach($passphrase as $p){
	
if(!is_string($p)){

throw new KEFException(1, 9, "Passphrase in array is not a string");

}

if(empty($p)){

throw new KEFException(1, 9, "Passphrase cannot be empty");

}

}

if(is_string($aad) && empty($aad)){
	
throw new KEFException(1, 4);

}

if(preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data)) || is_file($data)){
if($buffer_size > 0 && $buffer_size < Settings::DEFAULT_BUFFER_SIZE){
	
throw new KEFException(1, 9, "Less than default buffer size");

}

if($buffer_size == 0){
	
$buffer_size = Settings::DEFAULT_BUFFER_SIZE;

}

$path = $data;

$buffer_level = 1;

$buffer = buffer($data, $buffer_size, $buffer_level, true);

if(!hash_equals($info->getChecksum(true), $buffer[0]) || $buffer[1] != $info->getLength(true)){
	
throw new KEFException(1, 13);

}

$data = $buffer[2];
unset($buffer);

} else {
	
if(!hash_equals($info->getChecksum(true), md5($data)) || strlen($data) != $info->getLength(true)){
	
throw new KEFException(1, 13);

}

}

$decryption_info = $info->getDecryptionInfo();

if($decryption_info[2] > 0 && count($passphrase) == 1){

throw new KEFException(1, 9, "This file has been encrypted with multiple passphrases, only 1 passphrase is in array");
	
}

$multi_encrypt_split = $decryption_info[2];

$current_position = $decryption_info[4];

if(isset($path)){
	
while($current_position > $buffer_size){
	
$buffer_level++;
$current_position = $current_position - $buffer_size;

}

$data = buffer($path, $buffer_size, $buffer_level);

}

if($start < 0 || $end < 0 || $start >= $info->getLength() || $end > $info->getLength() - 1 || $end > 0 && $start >= $end){
	
throw new KEFException(1, 4);

}

$has_iv = false;

if(CipherTools::supportsIV($decryption_info[0]) > 0){
	
$has_iv = true;

}

$has_tag = false;

if(preg_match("/gcm|ccm/", $decryption_info[0])){

$has_tag = true;

}

if($end == 0){
	
$end = $info->getLength() - 1;

}

$trigger = 0;

if($start > $decryption_info[1]){
	
$offset = $start;

while($offset > $decryption_info[1]){
	
$offset = $offset - $decryption_info[1];

if($offset > $decryption_info[1]){
	
$trigger++;

if($multi_encrypt_split > 0){

if(!isset($multi_encrypt_split_current)){

$multi_encrypt_split_current = 1;

} else {

$multi_encrypt_split_current++;

}

if($multi_encrypt_split_current == $multi_encrypt_split){

$current_passphrase = next($passphrase);
$multi_encrypt_split_current = 0;

if($current_passphrase === false){
	
$current_passphrase = reset($passphrase);

}
	
}

}

if($has_iv){
	
$trigger++;

}

if($has_tag){
	
$trigger++;

}

}

}

}

if($trigger > 0){

if($has_iv){
	
$trigger--;

}

if($has_tag){
	
$trigger--;

}

}

$start_trigger = $trigger;

$trigger = 0;

if($end + 1 < $info->getLength()){
	
$trim = $end + 1;

while($trim > $decryption_info[1]){
	
$trim = $trim - $decryption_info[1];

if($trim > $decryption_info[1]){

$trigger++;

if($has_iv){
	
$trigger++;

}

if($has_tag){
	
$trigger++;

}

}

}

}

if($trigger > 0){

if($has_iv){
	
$trigger--;

}

if($has_tag){
	
$trigger--;

}

}

$end_trigger = $trigger;

unset($trigger);

$current_data = "";
$current_length = null;

$size_array_key = 0;
$decrypted_data = "";

if($multi_encrypt_split > 0 && !isset($multi_encrypt_split_current)){

$multi_encrypt_split_current = 0;

}

if(!isset($current_passphrase)){

$current_passphrase = reset($passphrase);

}

while(true){

if(is_null($current_length)){
	
$length = $decryption_info[3][$size_array_key];

} else {
	
$length = $current_length;

}

if(isset($path)){
	
$remaining = $buffer_size - $current_position;

if($remaining < $length){
	
$current_data = substr($data, $current_position, $remaining);

$remaining = $length - $remaining;

$current_position = $current_position + strlen($current_data);

while($remaining > 0){

if($current_position == $buffer_size){
	
$current_position = 0;

$buffer_level++;

$data = buffer($path, $buffer_size, $buffer_level);

}

$remainder = substr($data, $current_position, $remaining);

$current_position = $current_position + strlen($remainder);

$remaining = $remaining - strlen($remainder);

$current_data .= $remainder;

unset($remainder);

}

}

}

if(is_null($current_length)){

if(isset($remainder)){
	
$current_length = convertCharacter($remainder);

unset($remainder);

} else {
	
$current_length = convertCharacter(substr($data, $current_position, $length));

$current_position = $current_position + $length;

}

$size_array_key++;

continue;

}

if(!is_null($current_length)){

if(strlen($current_data) != $length){
	
$current_data = substr($data, $current_position, $length);

$current_position = $current_position + $length;

}

$current_length = null;

if($start_trigger > 0){
	
$start_trigger--;

}

if($end_trigger > 0){
	
$end_trigger--;

}

if($start_trigger == 0){

if(!isset($current_tag)){

if($has_tag){
	
$current_tag = $current_data;
$current_data = "";
continue;

} else {
	
$current_tag = null;

}

}

if(!isset($current_iv)){

if($has_iv){
	
$current_iv = $current_data;
$current_data = "";

continue;

} else {
	
$current_iv = null;

}

}

if(!is_null($current_tag)){

if(is_null($aad)){

$aad = "";

}

}

$decrypted = openssl_decrypt($current_data, $decryption_info[0], $current_passphrase, OPENSSL_RAW_DATA, $current_iv, $current_tag, $aad);

if(is_bool($decrypted) || is_null($decrypted)){
	
throw new KEFException(1, 3);

}
if(isset($offset)){
	
$decrypted_data .= substr($decrypted, $offset);
unset($offset);

} else if($end_trigger == 0 && isset($trim)){
	
$decrypted_data .= substr($decrypted, 0, $trim);
unset($trim);
break;

} else {
	
$decrypted_data .= $decrypted;

}

unset($decrypted);
unset($current_tag);
unset($current_iv);

$current_data = "";

if($multi_encrypt_split > 0){

$multi_encrypt_split_current++;

if($multi_encrypt_split_current == $multi_encrypt_split){

$current_passphrase = next($passphrase);
$multi_encrypt_split_current = 0;

if($current_passphrase === false){
	
$current_passphrase = reset($passphrase);

}
	
}

if(!isset($decryption_info[3][$size_array_key])){

break;

}

continue;

}

}

}

}

if($start == 0 && $end +1 == $info->getLength() && (strlen($decrypted_data) != $info->getLength() || !hash_equals($info->getChecksum(), md5($decrypted_data)))){
	
throw new KEFException(1, 13);

}

return $decrypted_data;

}












