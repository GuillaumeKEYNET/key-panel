	<div class="w100 txtcenter txtdarkblue mt3 mb3">
		
		Chargement
		<br />
		
		<img src="<?= URL ?>/assets/image/e-trans-logo.png" alt="CREDIT AGRICOLE BY PAYBOX" />
		
		<br />
		Veuillez patienter<br />...
		
	
	
<?php
	
	//mode d'appel
	$PBX_MODE        = '4';    //pour lancement paiement par exécution
	//$PBX_MODE        = '1';    //pour lancement paiement par URL
	
	//identification
	$PBX_SITE        = $payment_config->site ;
	$PBX_RANG        = $payment_config->rang ;
	$PBX_IDENTIFIANT = $payment_config->id ;
	
	//gestion de la page de connection : paramétrage "invisible"
	$PBX_WAIT			= '0';
	$PBX_TXT			= " ";
	$PBX_BOUTPI			= "nul";
	$PBX_BKGD			= "white";
	
	//informations paiement (appel)
	$PBX_TOTAL			= $total_commande*100 ;
	$PBX_DEVISE			= 978;
	$PBX_CMD			= $reference ;
	$PBX_PORTEUR		= $user_data['client_email'] ;
	
	//informations sécurité
	// $PBX_HASH			= "SHA512" ;	
	// $PBX_TIME			= date("c");
	// $publicKey			= $payment_config->public_key ;
	// $binKey 			= pack("H*", $keyTest);	//KEY en binaire.
	
	//informations nécessaires aux traitements (réponse)
	// $PBX_RETOUR			= "montant:M\;ref:R\;auto:A\;trans:T\;erreur:E\;sign:K";
	$PBX_RETOUR			= "montant:M\;ref:R\;auto:A\;trans:T\;erreur:E";
	$PBX_REPONDRE_A		= $payment_config->url_confirm ;				// IPN ?
	$PBX_EFFECTUE		= $payment_config->url_thanks ;
	$PBX_REFUSE			= $payment_config->url_error;
	$PBX_ANNULE			= $payment_config->url_error;
	//page en cas d'erreur
	$PBX_ERREUR			= $payment_config->url_error ;

	//construction de la chaîne de paramètres
	$PBX				= "PBX_MODE=$PBX_MODE PBX_SITE=$PBX_SITE PBX_RANG=$PBX_RANG PBX_IDENTIFIANT=$PBX_IDENTIFIANT PBX_WAIT=$PBX_WAIT PBX_TXT=$PBX_TXT PBX_BOUTPI=$PBX_BOUTPI PBX_BKGD=$PBX_BKGD PBX_TOTAL=$PBX_TOTAL PBX_DEVISE=$PBX_DEVISE PBX_CMD=$PBX_CMD PBX_PORTEUR=$PBX_PORTEUR PBX_REPONDRE_A=$PBX_REPONDRE_A PBX_EFFECTUE=$PBX_EFFECTUE PBX_REFUSE=$PBX_REFUSE PBX_ANNULE=$PBX_ANNULE PBX_ERREUR=$PBX_ERREUR PBX_RETOUR=$PBX_RETOUR";
	
	/*sécurité*/
	//HASH PBX + KEY
	// $hmac = strtoupper(hash_hmac('sha512', $PBX, $binKey));
	/*sécurité*/
	//NEW PBX : 
	// $PBX				.= " PBX_HMAC=".$hmac;
	
	//lancement paiement par exécution
	// echo $PBX;
	// echo "<br />publicKey: "; 
	// echo $publicKey;
	// echo "<br />binKey: "; 
	// echo $binKey;
	// echo "<br />hmac: "; 
	// echo $hmac;
	
	// $output = shell_exec( "https://preprod-tpeweb.paybox.com/cgi/MYchoix_pagepaiement.cgi $PBX" );
	$output = shell_exec( "../cgi-bin/modulev2.cgi $PBX" );
	echo $output;
		
	//lancement paiement par URL
	//"http://www.xxxxxxxxxx/modulev2.cgi?PBX_MODE=$PBX_MODE&PBX_SITE=$PBX_SITE&PBX_RANG=$PBX_RANG&PBX_IDENTIFIANT=$PBX_IDENTIFIANT&PBX_WAIT=$PBX_WAIT&PBX_TXT=$PBX_TXT&PBX_BOUTPI=$PBX_BOUTPI&PBX_BKGD=$PBX_BKGD&PBX_TOTAL=$PBX_TOTAL&PBX_DEVISE=$PBX_DEVISE&PBX_CMD=$PBX_CMD&PBX_PORTEUR=$PBX_PORTEUR&PBX_EFFECTUE=$PBX_EFFECTUE&PBX_REFUSE=$PBX_REFUSE&PBX_ANNULE=$PBX_ANNULE&PBX_ERREUR=$PBX_ERREUR&PBX_RETOUR=$PBX_RETOUR"

?>

	</div>