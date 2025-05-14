<?php
namespace tpkarras\KEF;

function encryptDataKEF($data, $passphrase, $cipher, $byte_range = 0, $aad = null, $output = null){
if(!is_string($data)){
Settings::throwException(0, 9, "Parameter \"\$data\" is required to be of type \"string\"");
}
if(!is_string($passphrase)){
Settings::throwException(0, 9, "Parameter \"\$passphrase\" is required to be of type \"string\"");
}
if(!is_string($cipher)){
Settings::throwException(0, 9, "Parameter \"\$cipher\" is required to be of type \"string\"");
}
if(!is_int($byte_range)){
Settings::throwException(0, 9, "Parameter \"\$cipher\" is required to be of type \"int\"");
}
if(!is_string($aad) && !is_null($aad)){
Settings::throwException(0, 9, "Parameter \"\$aad\" is required to be of type \"string/null\"");
}
if(!is_string($output) && !is_null($output)){
Settings::throwException(0, 9, "Parameter \"\$output\" is required to be of type \"string/null\"");
}
if(empty($data) || empty($passphrase) || empty($cipher) || $byte_range < 0 || is_string($output) && empty($output)){
Settings::throwException(0, 4);
}
if(version_compare(PHP_VERSION, "7.1.0") > -1 && is_string($aad) && empty($aad)){
Settings::throwException(0, 4);
}
if($byte_range !== 0 && ($byte_range < Settings::MIN_BYTES || $byte_range > Settings::MAX_BYTES)){
Settings::throwException(0, 1);
}
if($byte_range === 0){
$byte_range = Settings::DEFAULT_BYTE_RANGE;
}
$cipher_octet = CipherTools::convertCipher($cipher);
if(!empty($output)){
if(strpos(strtolower(PHP_OS), "win") !== false){
$excluded_characters = "/[\<\>\\\:\|\?\*]|CON|PRN|AUX|NUL|COM1|COM2|COM3|COM4|COM5|COM6|COM7|COM8|COM9|LPT1|LPT2|LPT3|LPT4|LPT5|LPT6|LPT7|LPT8|LPT9/";
if(preg_match($excluded_characters, $output)){
Settings::throwException(0, 9, "Excluded characters found");
}
}
foreach(str_split($output) as $v){
if(convertCharacter($v) <= 31){
Settings::throwException(0, 9, "Excluded characters found");
}
}
if(strpos($output, "/") !== false && !is_dir(preg_replace("/\/[^\/]+$/", "", $output))){
Settings::throwException(0, 9, "Not a directory");
}
if(is_file($output)){
Settings::throwException(0, 11);
}
if(file_put_contents($output, "") === false){
Settings::throwException(0, 10);
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
while($current_range < intval(ceil($total_length / $byte_range))){
if($iv_l === false){
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
if(version_compare(PHP_VERSION, "7.1.0") === -1){
$row = openssl_encrypt($r, $cipher, $passphrase, 0, $iv);
} else {
$row = openssl_encrypt($r, $cipher, $passphrase, 0, $iv, $tag, $aad);
}
if($row === false || $row === null){
Settings::throwException(2, 3);
}
if(version_compare(PHP_VERSION, "7.1.0") === -1 && preg_match("/gcm|ccm/", $cipher)){
if($iv !== null){
$tag = hash_hmac('sha256', $iv.$row, $passphrase, true);
} else {
$tag = hash_hmac('sha256', $row, $passphrase, true);
}
}
$length = convertCharacter(strlen($row));
array_unshift($octet_array[0], strlen($length));
$row = $length.$row;
if($iv  !== null){
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
}
$content_type = str_split($content_type, 1);
foreach($content_type as $k => $v){
$content_type[$k] = convertCharacter($v);
}
$checksum = str_split($checksum, 2);
foreach($checksum as $k => $v){
$checksum[$k] = hexdec($v);
}
array_unshift($octet_array, $cipher_octet, $total_length, $byte_range, $content_type, $checksum);
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

function buffer($data, $buffer_size = 0, $level = 1, $return_info = false){
if(!is_string($data)){
Settings::throwException(2, 9, "Parameter \"\$data\" is required to be of type \"string\"");
}
if(!is_int($buffer_size)){
Settings::throwException(2, 9, "Parameter \"\$buffer_size\" is required to be of type \"int\"");
}
if(!is_int($level)){
Settings::throwException(2, 9, "Parameter \"\$level\" is required to be of type \"int\"");
}
if(!is_bool($return_info)){
Settings::throwException(2, 9, "Parameter \"\$return_info\" is required to be of type \"bool\"");
}
if(empty($data)){
Settings::throwException(2, 4);
}
if($buffer_size < 0 || $level < 1){
Settings::throwException(2, 9, "Parameter(s) less than 0/1");
}
if($buffer_size > 0 && $buffer_size < Settings::DEFAULT_BUFFER_SIZE){
Settings::throwException(2, 9, "Less than default buffer size");
}
if($buffer_size === 0){
$buffer_size = Settings::DEFAULT_BUFFER_SIZE;
}
if(is_string($data) && preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data))){
$response_code = null;
$checksum = null;
$total_length = null;
$ch = curl_init($data);
curl_setopt($ch, CURLOPT_HTTPHEADER, ["Range: bytes=".$buffer_size * ($level - 1)."-".$buffer_size * $level - 1]);
curl_setopt($ch, CURLOPT_USERAGENT, "tpkarras/KEF/1.0.0 (https://github.com/tpkarras)");
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
    if(count($header) === 2){
    if(strtolower($header[0]) === "content-length" && is_null($total_length)){
$total_length = intval(trim($header[1]));
	}
    if(strtolower($header[0]) === "etag" && is_null($checksum)){
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
Settings::throwException(2, 12);
}
} else if(is_string($data) && is_file($data)){
$total_length = filesize($data);
$checksum = md5_file($data);
$data = fopen($data, "rb");
fseek($data, $buffer_size * ($level - 1));
$buffer = fread($data, $buffer_size);
if($buffer === false){
Settings::throwException(2, 12);
}
} else {
return false;
}
if(strlen($buffer) === 0){
Settings::throwException(2, 9, "Buffer is not supposed to be empty");
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
private $size_array = array();
private $cipher = null;
private $checksum_original = null;
private $checksum_kef = null;
private $data_start = null;

public function getContentType(){
return $this->content_type;
}

public function getDecryptionInfo(){
if(empty($this->size_array) || is_null($this->byte_range) || is_null($this->cipher) || is_null($this->data_start)){
return null;
}
$info = array();
$info[0] = $this->cipher;
$info[1] = $this->byte_range;
$info[2] = $this->size_array;
$info[3] = $this->data_start;
return $info;
}

public function getLength($type = false){
if(!is_bool($type)){
Settings::throwException(5, 9, "Parameter \"\$type\" is required to be of type \"bool\"");
}
if(!$type){
return $this->content_length;
} else {
return $this->kef_length;
}
}

public function getChecksum($type = false){
if(!is_bool($type)){
Settings::throwException(5, 9, "Parameter \"\$type\" is required to be of type \"bool\"");
}
if(!$type){
return $this->checksum_original;
} else {
return $this->checksum_kef;
}
}

private function clearData(){
if($this->cipher !== null){
$this->cipher = null;
}
if($this->content_length !== null){
$this->content_length = null;
}
if($this->kef_length !== null){
$this->kef_length = null;
}
if($this->checksum_original !== null){
$this->checksum_original = null;
}
if($this->checksum_kef !== null){
$this->checksum_kef = null;
}
if($this->byte_range !== null){
$this->byte_range = null;
}
if($this->content_type !== null){
$this->content_type = null;
}
if(count($this->size_array) > 0){
$this->size_array = array();
}
}

private function importData($data){
if(preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data))){
$data = htmlentities($data);
$data = buffer($data, 0, 1, true);
} else if(is_file($data)){
$data = buffer($data, 0, 1, true);
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
if(isset($is_buffer) && $current_position === $buffer_size * $buffer_level){
$data_start = $current_position + $data_start;
$buffer_level++;
$current_position = 0;
$data = buffer($data, 0, $buffer_level);
}
if($number === 255){
$size_array_element = $size_array_element + ($number >> 1) + 1;
} else if($number <= 128){
$size_array_element = $size_array_element + $number;
if($octet_count === null){
$octet_count = $size_array_element;
$size_array_element = 0;
continue;
}
} else if ($number > 128){
$this->clearData();
Settings::throwException(2, 8);
}
if($octet_count !== null){
if($this->cipher === null && isset($cipher)){
array_push($cipher, $size_array_element);
$size_array_element = 0;
} else if($this->content_length === null || $this->byte_range === null){
$octet_count--;
} else if($this->content_type === null || $this->checksum_original === null){
if($this->content_type === null){
$content_type .= convertCharacter($size_array_element);
$size_array_element = 0;
} else if($this->checksum_original === null){
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
if($this->cipher === null && count($cipher) === $octet_count){
try {
$this->cipher = CipherTools::convertCipher($cipher);
} catch (Exception $e){
$this->clearData();
throw $e;
}
unset($cipher);
$octet_count = null;
continue;
} else if($this->content_length === null && $octet_count === 0){
$this->content_length = $size_array_element;
$size_array_element = 0;
$octet_count = null;
continue;
} else if($this->byte_range === null && $octet_count === 0){
if($size_array_element < Settings::MIN_BYTES){
$this->clearData();
Settings::throwException(2, 1);
}
$this->byte_range = $size_array_element;
$size_array_element = 0;
$octet_count = null;
continue;
} else if($this->content_type === null && strlen($content_type) === $octet_count){
$this->content_type = $content_type;
unset($content_type);
$octet_count = null;
continue;
} else if($this->checksum_original === null && $octet_count === 0){
$this->checksum_original = $checksum;
unset($checksum);
$octet_count = null;
continue;
} else if(count($this->size_array) === $octet_count){
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
Settings::throwException(0, 9, "Parameter \"\$data\" is required to be of type \"string\"");
}
if(empty($data)){
Settings::throwException(0, 4);
}
$this->importData($data);
}

}

function decryptKEFData(KEFInfo $info, $data, $passphrase, $aad = null, $start = 0, $end = 0, $buffer_size = 0){
if(!is_string($data)){
Settings::throwException(0, 9, "Parameter \"\$data\" is required to be of type \"string\"");
}
if(!is_string($passphrase)){
Settings::throwException(0, 9, "Parameter \"\$passphrase\" is required to be of type \"string\"");
}
if(!is_string($aad) && !is_null($aad)){
Settings::throwException(0, 9, "Parameter \"\$aad\" is required to be of type \"string/null\"");
}
if(!is_int($start)){
Settings::throwException(0, 9, "Parameter \"\$start\" is required to be of type \"int\"");
}
if(!is_int($end)){
Settings::throwException(0, 9, "Parameter \"\$end\" is required to be of type \"int\"");
}
if(!is_int($buffer_size)){
Settings::throwException(0, 9, "Parameter \"\$end\" is required to be of type \"int\"");
}
if(is_null($info->getContentType()) || is_null($info->getDecryptionInfo()) || is_null($info->getLength()) || is_null($info->getChecksum())){
Settings::throwException(1, 7, "KEFInfo is invalid");
}
if(empty($data)){
Settings::throwException(1, 4);
}
if(empty($passphrase)){
Settings::throwException(1, 4);
}
if(version_compare(PHP_VERSION, "7.1.0") > -1 && is_string($aad) && empty($aad)){
Settings::throwException(1, 4);
}
if(preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data)) || is_file($data)){
if($buffer_size > 0 && $buffer_size < Settings::DEFAULT_BUFFER_SIZE){
Settings::throwException(1, 9, "Less than default buffer size");
}
if($buffer_size === 0){
$buffer_size = Settings::DEFAULT_BUFFER_SIZE;
}
$path = $data;
$buffer_level = 1;
$buffer = buffer($data, $buffer_size, $buffer_level, true);
if(!hash_equals($info->getChecksum(true), $buffer[0]) || $buffer[1] !== $info->getLength(true)){
Settings::throwException(1, 13);
}
$data = $buffer[2];
unset($buffer);
} else {
if(!hash_equals($info->getChecksum(true), md5($data)) || strlen($data) !== $info->getLength(true)){
Settings::throwException(1, 13);
}
}
$decryption_info = $info->getDecryptionInfo();
if($start < 0 || $end < 0 || $start >= $info->getLength() || $end > $info->getLength() - 1 || $end > 0 && $start >= $end){
Settings::throwException(1, 4);
}
$has_iv = false;
if(CipherTools::supportsIV($decryption_info[0]) > 0){
$has_iv = true;
}
$has_tag = false;
if(preg_match("/gcm|ccm/", $decryption_info[0])){
$has_tag = true;
}
if($end === 0){
$end = $info->getLength();
}
$trigger = 0;
if($start > $decryption_info[1]){
$offset = $start;
while($offset > $decryption_info[1]){
$offset = $offset - $decryption_info[1];
if($offset > $decryption_info[1]){
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
$start_trigger = $trigger;
$trigger = 0;
if($end < $info->getLength()){
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
$current_position = $decryption_info[3];
while(true){
if($current_length === null){
$length = $decryption_info[2][$size_array_key];
} else {
$length = $current_length;
}
if(isset($path)){
$remaining = $buffer_size - $current_position;
if($remaining < $length){
if($remaining > 0){
$remainder = substr($data, $current_position, $remaining);
$current_position = 0;
$buffer_level++;
$remaining = $length - $remaining;
$data = buffer($path, $buffer_size, $buffer_level);
$remainder .= substr($data, $current_position, $remaining);
$current_position = $current_position + $remaining;
$remaining = 0;
} else if($remaining === 0){
$current_position = 0;
$buffer_level++;
$data = buffer($path, $buffer_size, $buffer_level);
}
}
}
if($current_length === null){
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
if($current_length !== null){
if(isset($remainder)){
$current_data = $remainder;
unset($remainder);
} else {
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
if($start_trigger === 0){
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
if(version_compare(PHP_VERSION, "7.1.0") === -1){
if($current_tag !== null){
if($current_iv !== null){
$current_tag_compare = hash_hmac('sha256', $current_iv.$current_data, $passphrase, true);
} else {
$current_tag_compare = hash_hmac('sha256', $current_data, $passphrase, true);
}
if(!hash_equals($current_tag, $current_tag_compare)){
Settings::throwException(1, 3);
}
unset($current_tag_compare);
}
$decrypted = openssl_decrypt($current_data, $decryption_info[0], $passphrase, 0, $current_iv);
} else {
if(is_null($aad)){
$aad = "";
}
$decrypted = openssl_decrypt($current_data, $decryption_info[0], $passphrase, 0, $current_iv, $current_tag, $aad);
}
if($decrypted === false || $decrypted === null){
Settings::throwException(1, 3);
}
if(isset($offset)){
$decrypted_data .= substr($decrypted, $offset);
unset($offset);
} else if($end_trigger === 0 && isset($trim)){
$decrypted_data .= substr($decrypted, 0, $trim);
unset($trim);
break;
} else {
$decrypted_data .= $decrypted;
if(!isset($decryption_info[2][$size_array_key])){
if(strlen($decrypted_data) !== $info->getLength() || !hash_equals($info->getChecksum(), md5($decrypted_data))){
Settings::throwException(1, 13);
}
break;
}
}
unset($decrypted);
unset($current_tag);
unset($current_iv);
$current_data = "";
continue;
}
}
}
return $decrypted_data;
}
