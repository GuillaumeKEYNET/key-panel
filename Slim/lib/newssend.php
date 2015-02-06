<?php
session_start(); //Démarrer les sessions

//$SEND			= TRUE; 

$mail_from			= 'laetitia.guillaume@unbebealacle.net' ; 
$mail_to = $mail_cc = $mail_bcc = '' ; 

// $email_list			= "email_listing.txt" ; 
// $email_list			= "email_list.txt" ; 
$email_list			= "emailListeVague3_site_photos.txt" ; 
$email_content		= "emailVague3_Site_photos.txt" ; 

// $mail_subject		= "Un Bébé à la CLE.NET by KEYNET > ".date("ym-d-h:m:s"); ; 
$mail_subject		= "Photos de Noémie !" ; 


include( "lib/Email.php");
$email = new CI_Email;

//GET MESSAGE
$contenu = file_get_contents( $email_content , FILE_USE_INCLUDE_PATH); ;
$objet 	= $mail_subject; 

//GET ALL MAIL FROM LIST
$fp = fopen( $email_list  ,"r"); //lecture du fichier
$cibles = 'gussy@gussy.fr ';


/***************************************************************************************/
if( !($fp) OR !($contenu) )
{
	echo "FILE ERROR" ;
	exit;
}
/***************************************************************************************/
if( !(isset($SEND) && $SEND)  )
{
	echo $contenu ;
	exit;
}
/***************************************************************************************/
// Turn off output buffering
ini_set('output_buffering', 'off');
// Turn off PHP output compression
ini_set('zlib.output_compression', false);
         
//Flush (send) the output buffer and turn off output buffering
//ob_end_flush();
while (@ob_end_flush());
         
// Implicitly flush the buffer(s)
ini_set('implicit_flush', true);
ob_implicit_flush(true);
 
//prevent apache from buffering it for deflate/gzip
header("Content-type: text/html");
header('Cache-Control: no-cache'); // recommended to prevent caching of event data.
 
for($i = 0; $i < 1000; $i++)
{
echo ' ';
}
         
// ob_flush();
flush();


/***************************************************************************************/
//SEND EMAIL
// $config['protocol'] = 'mail';
// $config['mailpath'] = '/usr/sbin/sendmail';
$config['charset'] = 'UTF-8';
$config['wordwrap'] = TRUE;
$config['mailtype'] = 'text';
$config['protocol'] = 'smtp';
$config['smtp_host'] = "smtp.unbebealacle.net" ;
$config['smtp_user'] = "laetitia.guillaume@unbebealacle.net";
$config['smtp_pass'] = "taimtaim4212$*";

//SEND MAILS
while (!feof($fp)) 
{
	//on parcourt toutes les lignes
	$user_email = fgets($fp, 4096); 
	
	$email->clear();
	$email->initialize($config);
	$email->from($mail_from);
	// $email->to($mail_to);
	// $email->cc($mail_cc);
	// $email->bcc($mail_bcc);

	$email->subject( $objet );
	$email->message( $contenu );
	$email->to( $user_email );
		
	//SEND MAIL
	//envoi du mail 
	$send_ok  = $email->send();
	
	if( $send_ok )
		echo "<b>".$user_email."</b>"."<span style='color:green;'> >> OK</span>"."<hr />";
	else
	{
		echo "<b>".$user_email."</b>"."<span style='color:red;'> >> ERROR</span>"."<hr />".$email->print_debugger()."<hr />";
	}
	
	// ob_flush();
	flush();
	sleep(0.72);
}


echo "<h1>DONE ! </h1>"; 
echo $email_content ;
// ob_flush();
flush();








?>