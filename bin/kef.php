<?php
if(version_compare(PHP_VERSION, "5.6.0") === -1){
throw new Exception("Error loading KEF: PHP version is less than 5.6.0");
}
require("kef/settings.php");
require("kef/characters.php");
require("kef/ciphers.php");
require("kef/cryptography.php");
