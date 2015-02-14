<?php

define('APP_NAME', "Admin");
define('APP_LOGO', "");
define('APP_URL', "http://xxxxxxxxxxxxxxxx" );
define('APP_SECRET', "xxxxxxxxxxxxxxxx");
define('APP_DEFAULT', "/dashboard");

//***********************************************************
//INSTALL & ERASE
define('APP_INSTALL' , false );
define('APP_ERASE' , false );

//***********************************************************
//DEFINE PATHs
define('URL', APP_URL ."/admin");
define('PATH', "../data" );
define('RELATIVE_PATH', __DIR__ );

//***********************************************************
//DATABASE
$app->database = new medoo( array(
	'database_type' => 'mysql',
	'database_name' => 'xxxxxxxxxxxxxxxx',
	'server' => 'xxxxxxxxxxxxxxxx',
	'username' => 'xxxxxxxxxxxxxxxx',
	'password' => 'xxxxxxxxxxxxxxxx',
));

//***********************************************************
//DEFINE MAILS
// define( 'EMAIL_FROM' 		, 'infos@keynet.fr' );
// define( 'EMAIL_BCC' 			, '' );
