<?php
if(version_compare(PHP_VERSION, "7.4.0") == -1){

throw new Exception("Error loading KEF: PHP version is less than 7.4.0");

}
require("kef/settings.php");
require("kef/characters.php");
require("kef/ciphers.php");
require("kef/cryptography.php");
require("kef/exceptions.php");