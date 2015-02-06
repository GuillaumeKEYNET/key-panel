<?php

//------------------------------------------------
//DEFINE PATH for images
// define('URL', "http://motmotbiuc.cluster007.ovh.net");
define('URL', "http://www.motmotbijoux.com");
define('IMGPATH', URL."/data/img");
define('ASSETS', URL."/assets");

//------------------------------------------------
// set up database connection
$app->database = new medoo( array(
	'database_type' => 'mysql',
	'database_name' => 'motmotbiucbdd',
	'server' => 'mysql51-160.bdb',
	'username' => 'motmotbiucbdd',
	'password' => 'motmotPass12',
)); 

//------------------------------------------------
//ESHOP CONFIG
define( 'ESHOP_MAILTO' , 'hello@motmotbijoux.com ; dev@keynet.fr' );
define( 'ESHOP_MAILFROM' , 'hello@motmotbijoux.com' );

//------------------------------------------------
//PAYPAL CONFIG
// Modifier la valeur ci-dessous avec l'e-mail de vote compte PayPal
$app->paypal = new stdClass();

// /* Mode PROD */
$app->paypal->compte = 'hello@motmotbijoux.com';
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

$app->paypal->url_confirm = URL."/paypal/confirmation/m07m0781j0ux";
$app->paypal->url_thanks = URL."/checkout/merci";
$app->paypal->url_error = URL."/checkout/erreur";
//------------------------------------------------
//PAYBOX CONFIG
// Modifier la valeur ci-dessous avec l'e-mail de vote compte PayPal
$app->paybox = new stdClass();

/* Mode PROD */
$app->paybox->site = '1266343';
$app->paybox->rang = '01';
$app->paybox->id = '253939310';
$app->paybox->public_key = "" ; 
// /* Mode sandbox */
// $app->paybox->site = '1999888';
// $app->paybox->rang = '98';
// $app->paybox->id = '107975626';
// $app->paybox->id = '03';
// $app->paybox->public_key = "" ; 

$app->paybox->url_confirm = URL."/paybox/confirmation/m07m0781j0ux";
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