<?php

namespace tpkarras\KEF\Exceptions;

class NotSupportedError extends \Exception {
	
public function __construct() {

$message = "Operation is not supported.";

parent::__construct($message, 0, null);

}
	
}

class MissingRequiredParametersError extends \Exception {

public function __construct() {

$message = "Required parameters are missing";

parent::__construct($message, 1, null);

}
	
}

class MalformedDataError extends \Exception {
	
public function __construct() {

$message = "Data is malformed";

parent::__construct($message, 0, null);

}

}

class InvalidValueError extends \Exception {
	
public function __construct(string $additional) {

$message = "Invalid value";

	if(!empty($additional)){
	
	$message .= " (".$additional.")";
		
	}

parent::__construct($message, 1, null);

}

}

class FileError extends \Exception {

public function __construct(int $message) {

switch($message){

case 0:

$message = "File exists";
break;

case 1:

$message = "Not writable";
break;

case 2:

$message = "Buffer update failed";
break;

case 3:

$message = "Not a KEF file";
break;

}

parent::__construct($message, 0, null);

}
	
}

class OpenSSLError extends \Exception {

public function __construct(int $message) {

$message = "OpenSSL function has returned false";

parent::__construct($message, 0, null);

}
	
}

class ContentsCannotBeEmptyError extends \Exception {

public function __construct() {

$message = "Contents cannot be empty";

parent::__construct($message, 1, null);

}

}

class NotFoundError extends \Exception {

public function __construct() {

$message = "Match was not found";

parent::__construct($message, 1, null);

}

}

class AlreadySetError extends \Exception {

public function __construct() {

$message = "Value is already set";

parent::__construct($message, 2, null);

}

}

class NotSetError extends \Exception {

public function __construct() {

$message = "Value is empty/not set";

parent::__construct($message, 2, null);

}

}
