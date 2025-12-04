<?php
namespace tpkarras\KEF;

function convertCharacter($character){

if(!is_string($character) && !is_int($character)){

throw new KEFException(4, 9, "Parameter \"\$character\" is required to be of type \"int/string\"");

}

if(is_string($character)){

if(empty($character)){
throw new KEFException(4, 4);
}

$character_int = array();
$character = bin2hex($character);
$character = str_split($character, 2);

foreach($character as $c){
	
$c = hexdec($c);

if(!isset($temp_c)){

if($c <= hexdec("7F")){

array_push($character_int, $c);
continue;

} else {
	
$temp_c = 0;

if($c >= hexdec("C0") && $c <= hexdec("DF")){
	
if(count($character) != 2){
	
throw new KEFException(4, 7);

}

$multiplier = 1;
$subtractor = hexdec("C0");

} else if($c >= hexdec("E0") && $c <= hexdec("EF")){
	
if(count($character) != 3){
	
throw new KEFException(4, 7);

}

$multiplier = 2;
$subtractor = hexdec("E0");

} else if($c >= hexdec("F0") && $c <= hexdec("F7")){
	
if(count($character) != 4){

throw new KEFException(4, 7);

}

$multiplier = 3;
$subtractor = hexdec("F0");

} else if($c >= hexdec("F8") && $c <= hexdec("FB")){

if(count($character) != 5){

throw new KEFException(4, 7);

}

$multiplier = 4;
$subtractor = hexdec("F8");

} else if($c >= hexdec("FC") && $c <= hexdec("FD")){

if(count($character) != 6){
	
throw new KEFException(4, 7);

}

$multiplier = 5;
$subtractor = hexdec("FC");

} else {
	
return null;

}

}

}

if($multiplier > 0){
	
if(isset($subtractor)){
	
$c = $c - $subtractor;
unset($subtractor);

} else {
	
$c = $c - hexdec("80");

}

$c = $c * pow(2, (6 * $multiplier));
$multiplier--;

$temp_c = $temp_c + $c;

} else {
	
$c = $c - hexdec("80");

$temp_c = $temp_c + $c;

array_push($character_int, $temp_c);

unset($temp_c);

}

}

if(count($character_int) > 1){
	
throw new KEFException(4, 9, "Input can only be one character");

}

return $character_int[0];

} else {
	
if($character < 0){
	
throw new KEFException(4, 9, "Parameter less than 0");

}

if($character <= hexdec("0000007F")){
	
$character = dechex($character);

if(strlen($character) & 1){
	
$character = "0".$character;

}

return hex2bin($character);

} else {
	
$temp_c = "";

if($character <= hexdec("000007FF")){
	
$multiplier = 1;
$start = hexdec("C0");

} else if($character >= hexdec("00000800") && $character <= hexdec("0000FFFF")){
	
$multiplier = 2;
$start = hexdec("E0");

} else if($character >= hexdec("00001000") && $character <= hexdec("001FFFFF")){
	
$multiplier = 3;
$start = hexdec("F0");

} else if($character >= hexdec("00200000") && $character <= hexdec("03FFFFFF")){
	
$multiplier = 4;
$start = hexdec("F8");

} else if($character >= hexdec("04000000") && $character <= hexdec("7FFFFFFF")){
	
$multiplier = 5;
$start = hexdec("FC");

} else {
	
return null;

}

while($multiplier > 0){

if(isset($start)){

$temp_c .= dechex($start + ($character / pow(2, (6 * $multiplier))));
unset($start);

} else {
	
$temp_c .= dechex(hexdec("80") + ($character / pow(2, (6 * $multiplier)) % pow(2, 6)));

}

$multiplier--;

}

$temp_c .= dechex(hexdec("80") + ($character % pow(2, 6)));

return hex2bin($temp_c);

}

}

}
