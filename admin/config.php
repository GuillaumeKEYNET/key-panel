<?php

define('APP_NAME', "MOTMOT BIJOUX - Admin");
define('APP_LOGO', "../assets/images/logo_motmot_white.png");
define('APP_URL', "http://www.motmotbijoux.com" );
define('APP_SECRET', "motmotbijoux");
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
	'database_name' => 'motmotbiucbdd',
	'server' => 'mysql51-160.bdb',
	'username' => 'motmotbiucbdd',
	'password' => 'motmotPass12',
));

//***********************************************************
//DEFINE MAILS
// define( 'EMAIL_FROM' 		, 'infos@keynet.fr' );
// define( 'EMAIL_BCC' 			, '' );
