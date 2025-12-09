<?php

namespace tpkarras\KEF;

class KEFException extends \Exception {
	
public function __construct(int $job, int $exception, string|null $additional = null, Throwable|null $previous = null) {

	if($job < 0 || $exception < 0){
	
	throw new \Exception("Error throwing exception: Parameters cannot be less than 0");

	}

	if(!is_null($additional) && empty($additional)){
	
	throw new \Exception("Error throwing exception: Additional message cannot be empty");

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
	
	$message = "Error throwing exception: Job not found";

	}

	if(array_search($exception, $check) === false){
	
	$message = "Error throwing exception: Job does not support message";

	}

	if(!isset($message)){

	unset($check);

	$code = 0;

	switch($exception){
	
		case 0:

		$exception = "Unsupported";
		$code = 1;

		break;

		case 1:

		$exception = "Not within range";
		$code = 1;

		break;

		case 2:

		$exception = "Missing Passphrase";
		$code = 1;

		break;

		case 3:

		$exception = "OpenSSL function returned false";
		$code = 1;

		break;

		case 4:
		
		$exception = "Cannot be empty";
		break;

		case 5:

		$exception = "Not found";
		break;

		case 6:

		$exception = "Already set";
		$code = 1;

		break;

		case 7:

		$exception = "Malformed data";
		$code = 1;

		break;

		case 8:

		$exception = "Not KEF";
		break;

		case 9:

		$exception = "Does not conform";
		$code = 1;

		break;

		case 10:

		$exception = "Not writable";
		$code = 1;

		break;

		case 11:

		$exception = "File exists";
		$code = 1;

		break;

		case 12:

		$exception = "Buffer update failed";
		$code = 1;

		break;

		case 13:

		$exception = "Does not match";
		$code = 1;

	}

		if(!is_null($additional)){
	
		$exception .= " (".$additional.")";

		}

	$message = $job.": ".$exception;

	}

parent::__construct($message, $code, $previous);

}


}
