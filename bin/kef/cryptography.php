<?php
namespace tpkarras\KEF;

//Encrypt Data to KEF format
function encryptData(string $data, array $passphrase, string $cipher, int $byte_range = 0, int $multi_encrypt_split = 0, string|null $aad = null, string|null $output = null){

	if(empty($data) || empty($passphrase) || empty($cipher) || $byte_range < 0 || $multi_encrypt_split < 0 || is_string($output) && empty($output)){
	
	throw new KEFException(0, 4);

	}

//Check if passphrases are non-empty strings
foreach($passphrase as $p){
	
	if(!is_string($p)){
	
	throw new KEFException(0, 9, "Passphrase in array is not a string");

	}

	if(empty($p)){

	throw new KEFException(0, 9, "Passphrase cannot be empty");
	
	}

}

//Check for GCM/CCM mode
	if(!preg_match("/gcm$|ccm$/", $cipher)){

	throw new KEFException(0, 0, "Cipher is not GCM/CCM");

	}

//Check if optional AAD string is empty
	if(is_string($aad) && empty($aad)){
	
	throw new KEFException(0, 4);

	}

//Check if byte range is within the MIN/MAX range
	if($byte_range != 0 && ($byte_range < Settings::MIN_BYTES || $byte_range > Settings::MAX_BYTES)){
	
	throw new KEFException(0, 1);

	}

//If byte range is 0, set default byte range parameter
	if($byte_range == 0){

	$byte_range = Settings::DEFAULT_BYTE_RANGE;

	}

//Convert cipher to array for header insertion
$cipher_octet = CipherTools::convertCipher($cipher);

//Check optional output path for forbidden characters, check if file exists and check if writable
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

//Load data
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

//Prepare for encryption
$current_data = "";

	if(is_null($aad)){
	
	$aad = "";

	}

$current_range = 0;

$octet_array = array(array());

//Check if cipher supports IV
$iv_l = CipherTools::supportsIV($cipher);

//For more than one passphrase
	if(count($passphrase) > 1){

	$multi_encrypt_split_current = 0;

//Set default multi-encrypt split parameter if 0
		if($multi_encrypt_split == 0){

		$multi_encrypt_split = Settings::DEFAULT_BYTE_MULTI_ENCRYPT_SPLIT;

		} 

//Check if multi-encrypt split not greater than maximum number of ranges
		if ($multi_encrypt_split > intval(floor(ceil($total_length / $byte_range) / count($passphrase)))){

		throw new KEFException(0, 9, "Multi-encrypt split exceeds maximum number of ranges.");

		}

	}

//Initialize passphrase
$current_passphrase = reset($passphrase);

//Encryption loop
while($current_range < intval(ceil($total_length / $byte_range))){

//Generate IV if supported
	if(!$iv_l){
	
	$iv = null;

	} else {
	
	$iv = openssl_random_pseudo_bytes($iv_l);

	}

//Initialize tag variable
$tag = null;

//Read data from file or array
	if(!is_array($data)){
	
	$r = fread($data, $byte_range);

	} else {
	
	$r = $data[$current_range];

	}

//Call encryption function
$row = openssl_encrypt($r, $cipher, $current_passphrase, OPENSSL_RAW_DATA, $iv, $tag, $aad);

	if(is_bool($row) || is_null($row)){
	
	throw new KEFException(2, 3);

	}

//Insert length characters
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

//Buffer
	if(isset($tmp_file)){

		if(!isset($buffer)){
	
		$buffer = strlen($row);

		} else {
	
		$buffer = $buffer + strlen($row);

		}

//Append data
	fwrite($tmp_file, $row);

	} else {
	
	$current_data .= $row;

	}

unset($row);

$current_range++;

//Cycle through passphrases
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

//Header preperation

//Content type
$content_type = str_split($content_type, 1);

foreach($content_type as $k => $v){
	
$content_type[$k] = convertCharacter($v);

}

//Checksum
$checksum = str_split($checksum, 2);

foreach($checksum as $k => $v){
	
$checksum[$k] = hexdec($v);

}

//Array initialization
array_unshift($octet_array, $cipher_octet, $total_length, $byte_range, $multi_encrypt_split, $content_type, $checksum);

$octets = "";
$current_octet = "";

//Octet creation
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

//File creation
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

//Class for KEF encrypted files
class KEFData {

private $data = null;
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
private $buffer_size = null;

public function setBufferSize(int $buffer_size){

	if($buffer_size < Settings::MIN_BUFFER_SIZE){

	$this->clearData();

	throw new KEFException(3, 9, "Less than minimum buffer size");

	}

$this->buffer_size = $buffer_size;

}

//Buffer to store data on memory temporarily
private function buffer(int $level = 1){

	if($level < 1){
	
	throw new KEFException(2, 9, "Parameter \"level\" less than 1");

	}

//CURL buffer
	if(is_string($this->data) && preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data))){
	
	$response_code = null;

	$checksum = null;

	$total_length = null;

	$ch = curl_init($this->data);

	curl_setopt($ch, CURLOPT_HTTPHEADER, ["Range: bytes=".$this->buffer_size * ($level - 1)."-".$this->buffer_size * $level - 1]);

	curl_setopt($ch, CURLOPT_USERAGENT, "tpkarras/KEF/1.5.25 (https://github.com/tpkarras)");

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

//File buffer
	} else {

	fseek($this->data, $this->buffer_size * ($level - 1));

	$buffer = fread($this->data, $this->buffer_size);

		if($buffer === false){
	
		throw new KEFException(2, 12);

		}

	rewind($this->data);

	}

	if(strlen($buffer) == 0){
	
	throw new KEFException(2, 9, "Buffer is not supposed to be empty");

	}

//Array for CURL buffer info
	if(is_string($this->data) && preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($this->data))){
	
	$info = array();

	$info[0] = $checksum;
	$info[1] = $total_length;
	$info[2] = $buffer;

	return $info;

	} else {
	
	return $buffer;

	}

}

public function getContentType(){
	
return $this->content_type;

}

//Content length for original and encrypted file
public function getLength(bool $type = false){

	if(!$type){
	
	return $this->content_length;

	} else {
	
	return $this->kef_length;

	}

}

//Checksum for original and encrypted file
public function getChecksum(bool $type = false){

	if(!$type){
	
	return $this->checksum_original;

	} else {
	
	return $this->checksum_kef;

	}

}

//Internal function to clean up failed initialization
private function clearData(){

	if(!is_null($this->buffer_size)){

	$this->buffer_size = null;

	}

	if(!is_null($this->data)){

		if(is_resource($this->data)){

		fclose($this->data);

		}

	$this->data = null;

	}

	if(!is_null($this->cipher)){
	
	$this->cipher = null;

	}

	if(!is_null($this->content_length)){
	
	$this->content_length = null;

	}

	if(!is_null($this->kef_length)){
	
	$this->kef_length = null;

	}

	if(!is_null($this->checksum_original)){
	
	$this->checksum_original = null;

	}

	if(!is_null($this->checksum_kef)){
	
	$this->checksum_kef = null;

	}

	if(!is_null($this->byte_range)){
	
	$this->byte_range = null;

	}

	if(!is_null($this->multi_encrypt_split)){
	
	$this->byte_range = null;

	}

	if(!is_null($this->content_type)){
	
	$this->content_type = null;

	}

	if(count($this->size_array) > 0){
	
	$this->size_array = array();

	}

}

//Internal function to import data
private function importData(string $data){

//Prepare data if file/URL/string
	if(preg_match("/^https?\:\/\/(?:www\.)?[^\s]+(?:\.[a-z])+/", strtolower($data))){
	
	$data = htmlentities($data);

	$this->data = $data;

	} else if(is_file($data)){

	$total_length = filesize($data);

	$checksum = md5_file($data);

	$this->data = fopen($data, "rb");

	} else {

	$this->checksum_kef = md5($data);

	$this->kef_length = strlen($data);

	$this->data = tmpfile();

	fwrite($this->data, $data);

	rewind($this->data);

	}

//Preperation

$buffer_level = 1;

$data = $this->buffer($buffer_level);

	if(is_array($data)){

	$this->checksum_kef = $data[0];

	$this->kef_length = $data[1];

	$data = $data[2];

	}

$current_position = 0;
$data_start = 0;
$octet_count = null;
$size_array_element = 0;
$content_type = "";
$checksum = "";
$cipher = [];

//Load data
while(true){
	
$number = hexdec(bin2hex(substr($data, $current_position, 1)));

$current_position++;

//Buffer if end of data
	if($current_position == $this->buffer_size){
	
	$data_start = $current_position + $data_start;

	$buffer_level++;

	$current_position = 0;

	$data = $this->buffer($buffer_level);

		if(is_array($data)){

		$data = $data[2];

		}

	}

//Octet conversion
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

//Data population
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

//Initialization function
public function __construct(string $data, int $buffer_size = 0){

	if(empty($data)){
	
	throw new KEFException(0, 4);

	}

	if($buffer_size != 0){
	
	$this->setBufferSize($buffer_size);

	} else {
	
	$this->buffer_size = Settings::MIN_BUFFER_SIZE;

	}

$this->importData($data);

}

//Decryption function
public function decrypt(array $passphrase, string|null $aad = null, int $start = 0, int $end = 0){

	if(empty($passphrase)){
	
	throw new KEFException(1, 4);

	}

//Check if passphrases are non-empty strings
foreach($passphrase as $p){
	
	if(!is_string($p)){

	throw new KEFException(1, 9, "Passphrase in array is not a string");

	}

	if(empty($p)){

	throw new KEFException(1, 9, "Passphrase cannot be empty");

	}

}

//Check if AAD is a non-empty string
	if(is_string($aad) && empty($aad)){
	
	throw new KEFException(1, 4);

	}

//Multiple passphrases requirement if file was encrypted with multi-encrypt feature
	if($this->multi_encrypt_split > 0 && count($passphrase) == 1){

	throw new KEFException(1, 9, "This file has been encrypted with multiple passphrases, only 1 passphrase is in array");
	
	}

$multi_encrypt_split = $this->multi_encrypt_split;

//Decryption preperation

$current_position = $this->data_start;
	
while($current_position > $this->buffer_size){
	
$buffer_level++;
$current_position = $current_position - $this->buffer_size;

}

$buffer_level = 1;

$data = $this->buffer($buffer_level);

	if(is_array($data)){

	$data = $data[2];

	}

//Check if valid range

	if($start < 0 || $end < 0){
	
	throw new KEFException(1, 9, "\"\$start\"/\"\$end\" cannot be less than 0");

	}

	if($start >= $this->content_length - 1 || $end > $this->content_length - 1){
	
	throw new KEFException(1, 9, "\"\$start\"/\"\$end\" greater than original byte range");

	}

	if($end > 0 && ($start >= $end || $end <= $start)){

	throw new KEFException(1, 9, "\"\$start\"/\"\$end\" has invalid range");

	}

$has_iv = false;

	if(CipherTools::supportsIV($this->cipher) > 0){
	
	$has_iv = true;

	}

$has_tag = false;

	if(preg_match("/gcm|ccm/", $this->cipher)){

	$has_tag = true;

	}

//Set up triggers

	if($end == 0){
	
	$end = $this->content_length - 1;

	}

$trigger = 0;

$offset = $start;

	if($offset >= $this->byte_range){

	while($offset >= $this->byte_range){
	
	$offset = $offset - $this->byte_range;
	
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

		if($has_tag || $has_iv){

		$trigger++;

		}

	}

$start_trigger = $trigger;
$trigger = 0;
$trim = $end + 1;

	if($end - $start > $this->byte_range){

	while($trim > $this->byte_range){

	$trim = $trim - $this->byte_range;

	$trigger++;

		if($has_iv){
	
		$trigger++;

		}

		if($has_tag){
	
		$trigger++;

		}

	}

	}

$end_trigger = $trigger - $start_trigger;

while($end_trigger < 0){

$end_trigger++;

}

unset($trigger);

//Second preperation phase

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

$started = false;

//Decryption loop

while(true){

//Get length character

	if(is_null($current_length)){
	
	$length = $this->size_array[$size_array_key];

	} else {
	
	$length = $current_length;

	}

//Buffer
	
$remaining = $this->buffer_size - $current_position;

	if($remaining < $length){
	
	$current_data = substr($data, $current_position, $remaining);

	$remaining = $length - $remaining;

	$current_position = $current_position + strlen($current_data);

	while($remaining > 0){

		if($current_position == $this->buffer_size){
	
		$current_position = 0;

		$buffer_level++;

		$data = $this->buffer($buffer_level);

			if(is_array($data)){

			$data = $data[2];

			}

		}

	$remainder = substr($data, $current_position, $remaining);

	$current_position = $current_position + strlen($remainder);

	$remaining = $remaining - strlen($remainder);

	$current_data .= $remainder;

	unset($remainder);

	}

	}

//Convert length character

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

//Retrieve data with length from character

	if(!is_null($current_length)){

		if(strlen($current_data) != $length){
	
		$current_data = substr($data, $current_position, $length);

		$current_position = $current_position + $length;

		}

	$current_length = null;

		if($started && $end_trigger > 0){

		$end_trigger--;

		} else if($start_trigger > 0){

		$start_trigger--;

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

//Decrypt function

	$decrypted = openssl_decrypt($current_data, $this->cipher, $current_passphrase, OPENSSL_RAW_DATA, $current_iv, $current_tag, $aad);

		if(!$started){
	
		$started = true;

		}

//Check if decryption worked

		if(is_bool($decrypted) || is_null($decrypted)){
	
		throw new KEFException(1, 3);

		}

//Retrieve range of data

//Start
		if(isset($offset)){

		$decrypted = substr($decrypted, $offset);

			if($end_trigger == 0){
	
			$trim = $trim - $offset;

			}

		unset($offset);

		}

//End
		if($end_trigger == 0 && isset($trim)){

		$decrypted = substr($decrypted, 0, $trim);
		$decrypted_data .= $decrypted;

		unset($trim);

		} else {

		$decrypted_data .= $decrypted;

		}

		unset($decrypted);
		unset($current_tag);
		unset($current_iv);

		$current_data = "";

//Cycle through passphrases
			if($multi_encrypt_split > 0){

			$multi_encrypt_split_current++;

				if($multi_encrypt_split_current == $multi_encrypt_split){

				$current_passphrase = next($passphrase);
				$multi_encrypt_split_current = 0;

					if($current_passphrase === false){
	
					$current_passphrase = reset($passphrase);

					}
	
				}

//Finally
				if($end_trigger == 0 || !isset($this->size_array[$size_array_key])){

				break;

				}

			continue;

			}

		}

	}

}

unset($started);

	if($start == 0 && $end +1 == $this->content_length && (strlen($decrypted_data) != $this->content_length || !hash_equals($this->checksum_original, md5($decrypted_data)))){
	
	throw new KEFException(1, 13);

	}

return $decrypted_data;

}

}

