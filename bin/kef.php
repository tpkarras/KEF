<?php
/*
KEF v1.5.25 by tpkarras (https://github.com/tpkarras/KEF)
This code is licensed under the GNU General Public License v3.0
*/

if(version_compare(PHP_VERSION, "7.4.0") == -1){

throw new Exception("Error loading KEF: PHP version is less than 7.4.0");

}
require("kef/settings.php");
require("kef/characters.php");
require("kef/ciphers.php");
require("kef/cryptography.php");
require("kef/exceptions.php");