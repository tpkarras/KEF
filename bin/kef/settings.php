<?php
namespace tpkarras\KEF;

class Settings{

public const MIN_BYTES = 2;
public const MAX_BYTES = 1024000000;
public const DEFAULT_BYTE_RANGE = 16384;
public const DEFAULT_BUFFER_SIZE = 2560000;

public static function throwException($job, $message, $additional = null){
	
if(!is_int($job)){
	
throw new \Exception("Error: Parameter \"\$job\" is required to be of type \"int\"");

}
if(!is_int($message)){
	
throw new \Exception("Error: Parameter \"\$message\" is required to be of type \"int\"");

}
if(!is_string($additional) && !is_null($additional)){
	
throw new \Exception("Error: Parameter \"\$additional\" is required to be of type \"string/null\"");

}
if($job < 0 || $message < 0){
	
throw new \Exception("Error: Job and message cannot be less than 0");

}

if(!is_null($additional) && empty($additional)){
	
throw new \Exception("Error: Additional message cannot be empty");

}

switch($job){
	
case 0:

$job = "Error encrypting";
$check = [0, 1, 2, 3, 4, 5, 9, 10, 11];

break;

case 1:

$job = "Error decrypting";
$check = [0, 3, 4, 7, 9, 13];

break;

case 2:

$job = "Error loading data";
$check = [1, 4, 5, 6, 8, 9, 12];

break;

case 3:

$job = "Error setting";
$check = [0, 4, 6, 9];

break;

case 4:

$job = "Error checking/converting";
$check = [0, 4, 5, 7, 9];

break;

case 5:

$job = "Error retrieving";
$check = [9];

}

if(!is_string($job)){
	
throw new \Exception("Error: Job not found");

}

if(array_search($message, $check) === false){
	
throw new \Exception("Error: Job does not support message");

}

unset($check);

$code = 0;

switch($message){
	
case 0:

$message = "Unsupported";
$code = 1;

break;

case 1:

$message = "Not within range";
$code = 1;

break;

case 2:

$message = "Missing Passphrase";
$code = 1;

break;

case 3:

$message = "OpenSSL function returned false";
$code = 1;

break;

case 4:

$message = "Cannot be empty";
break;

case 5:

$message = "Not found";
break;

case 6:

$message = "Already set";
$code = 1;

break;

case 7:

$message = "Malformed data";
$code = 1;

break;

case 8:

$message = "Not KEF";
break;

case 9:

$message = "Does not conform";
$code = 1;

break;

case 10:

$message = "Not writable";
$code = 1;

break;

case 11:

$message = "File exists";
$code = 1;

break;

case 12:

$message = "Buffer update failed";
$code = 1;

break;

case 13:

$message = "Does not match";
$code = 1;

}

if(!is_null($additional)){
	
$message .= " (".$additional.")";

}

throw new \Exception($job.": ".$message, $code);

}

}
