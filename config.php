<?php

//------------------------------------------------
//DEFINE PATH for images
define('URL', "http://xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
define('IMGPATH', URL."/data/img");
define('ASSETS', URL."/assets");

//------------------------------------------------
// set up database connection
$app->database = new medoo( array(
	'database_type' => 'mysql',
	'database_name' => 'xxxxxxxxxxxxxxxx',
	'server' => 'xxxxxxxxxxxxxxxx',
	'username' => 'xxxxxxxxxxxxxxxx',
	'password' => 'xxxxxxxxxxxxxxxx',
)); 

//------------------------------------------------
//ESHOP CONFIG
define( 'ESHOP_MAILTO' , 'xxxxxxxxxxxxxxxx' );
define( 'ESHOP_MAILFROM' , 'xxxxxxxxxxxxxxxx' );

//------------------------------------------------
//PAYPAL CONFIG
// Modifier la valeur ci-dessous avec l'e-mail de vote compte PayPal
$app->paypal = new stdClass();

// /* Mode PROD */
$app->paypal->compte = 'xxxxxxxxxxxxxxxx';
$app->paypal->devise        = "EUR";
$app->paypal->code_langue   = "FR";
$app->paypal->serveur = "https://www.paypal.com/cgi-bin/webscr";
$app->paypal->ipn_serveur   = "ssl://www.paypal.com/cgi-bin/webscr";
$app->paypal->port   = 443 ;
// /* Mode sandbox */
// $app->paypal->compte = 'dev-facilitator@keynet.fr';
// $app->paypal->serveur   = "https://www.sandbox.paypal.com/cgi-bin/webscr";
// $app->paypal->devise        = "EUR";
// $app->paypal->code_langue   = "FR";
// $app->paypal->ipn_serveur   = "ssl://www.sandbox.paypal.com/cgi-bin/webscr";
// $app->paypal->port   = 443 ;

$app->paypal->url_confirm = URL."/paypal/confirmation/xxxxxxxxxxxxxxxx";
$app->paypal->url_thanks = URL."/checkout/merci";
$app->paypal->url_error = URL."/checkout/erreur";
//------------------------------------------------
//PAYBOX CONFIG
// Modifier la valeur ci-dessous avec l'e-mail de vote compte PayPal
$app->paybox = new stdClass();

/* Mode PROD */
$app->paybox->site = 'xxxxxxxxxxxxxxxx';
$app->paybox->rang = 'xxxxxxxxxxxxxxxx';
$app->paybox->id = 'xxxxxxxxxxxxxxxx';
$app->paybox->public_key = "" ; 
// /* Mode sandbox */
// $app->paybox->site = '1999888';
// $app->paybox->rang = '98';
// $app->paybox->id = '107975626';
// $app->paybox->id = '03';
// $app->paybox->public_key = "" ; 

$app->paybox->url_confirm = URL."/paybox/confirmation/xxxxxxxxxxxxxxxx";
$app->paybox->url_thanks = URL."/checkout/merci";
$app->paybox->url_error = URL."/checkout/erreur";
$app->paybox->ip_ipn = array('194.2.122.158' , '195.25.7.166') ; 

//------------------------------------------------
//EMAIL CONFIG 
$app->email = new CI_Email;
$email_config['protocol'] = 'mail';
// $email_config['mailpath'] = '/usr/sbin/sendmail';
$email_config['charset'] = 'UTF-8';
$email_config['wordwrap'] = TRUE;
$email_config['mailtype'] = 'html';
// $email_config['smtp_host'] = "smtp.xXXXXX" ;
// $email_config['smtp_user'] = "contact@XXXXXXX";
// $email_config['smtp_pass'] = "";

$app->email->initialize($email_config);
$app->email->from( ESHOP_MAILFROM );
// $app->email->to('dev@keynet.fr');
// $app->email->cc();
$app->email->bcc( ESHOP_MAILTO );





?>