<?php

//******************************************************************************
// ESHOP - PRODUCT
$app->get('/eshop-(:category_slug)/(:product_id)~(:product_slug)', function ( $category_slug , $product_id , $product_slug ) use ($app) {
	
	//GET CATEGORY
	$product = $app->database->get( 'eshop_product' , '*' , array( "AND" => array( "id" => $product_id ,  "slug" => $product_slug ) ) );

	//404
	if( !$product ) { $app->notFound(); exit; }
	
	//GET CATEGORY BY PRODUCT
	$product['category'] = $app->database->get( 'eshop_category' , '*' , array( "id" => $product['eshop_category_id'] ) );

	//METAS
	$meta = array(
		'title' => $product['name'].' - ' ,
		'description' => $product['meta_description'] ,
		'url' => '/eshop-'.$category_slug ,
	);

	//RENDER
	$app->render('product.view.php', array(
		'product' => $product,
		'meta' => $meta,
	) );
		
   
});
//******************************************************************************
// ESHOP - CATEGORY
$app->get('/eshop-(:category_slug)', function ( $category_slug ) use ($app) {
   
	//GET CATEGORY
	$category = $app->database->get( 'eshop_category' , '*' , array( "slug" => $category_slug ) );

	//404
	if( !$category ) { $app->notFound(); exit; }

	//GET PRODUCT LIST
	$products = $app->database->query( "SELECT * FROM eshop_product WHERE visible = 1 AND eshop_category_id = ".$category['id']." ORDER BY orden" )->fetchAll();
	//GET CATEGORY BY PRODUCT
	foreach( $products as $key => $item )
	{
		//GET CATEGORY BY PRODUCT
		$products[$key]['category'] = $app->database->get( 'eshop_category' , '*' , array( "id" => $item['eshop_category_id'] ) );
		
		//SET URL
		$products[$key]['url'] = URL.'/eshop-'.$products[$key]['category']['slug'].'/'.$item['id'].'~'.$item['slug'] ;
	}

	//METAS
	$meta = array(
		'title' => $category['name'].' - ' ,
		'description' => '' ,
		'url' => '/eshop-'.$category_slug ,
	);

	//RENDER
	$app->render('category.view.php', array(
		'category' => $category,
		'products' => $products,
		'meta' => $meta,
	) );
		
   
});


//******************************************************************************
//ESHOP : ADD TO CART
$app->map( '/eshop/addtocart', function () use ($app) 
{
	$data= array();
	//GET REQUEST DATA
	$data['product_id'] 		= $app->request->params('product_id') ; 
	$data['quantity'] 			= $app->request->params('quantity') ; 
	
	// var_dump( $data['product_infos'] );exit;
	// implode($data['product_infos'] , "<br />");exit;
	// echo implode('<br />', array_map(function ($v, $k) { return $k . '=' . $v ; }, $data['product_infos'], array_keys($data['product_infos']))); 
	 
	//SAVE CART
	$_SESSION['cart'][] = $data ;
	
	//DATABASE : INSERT 
	// $data['user_id'] = $app->database->insert('KEYNET_charte_form_user' , $data );
	
	
	
	//REDIRECT 
	$app->redirect(URL.'/eshop/cart');
	
		
})->via('GET', 'POST');
//******************************************************************************

//******************************************************************************
//ESHOP : REMOVE CART
$app->map( '/eshop/removefromcart', function () use ($app) 
{
	//GET REQUEST DATA
	$cart_key =  $app->request->params('key') ;
	
	//UNSET CART KEY
	unset($_SESSION['cart'][$cart_key] );
	
	//REDIRECT 
	$app->redirect(URL.'/eshop/cart');
	
	
	
})->via('GET', 'POST');
//******************************************************************************

//******************************************************************************
//ESHOP : PANIER CART
$app->get( '/eshop/cart', function () use ($app) 
{
	//GET panier
	$cart = $_SESSION['cart'] ;
	
	//GET CART TOTAL
	$cart_total = 0;
	foreach( $cart as $key => $item )
	{
		$cart[$key]['product'] 				= $app->database->get("eshop_product" , "*", array( 'AND' => array( "id" => $item['product_id'] , "visible" => "1" ))  );
		$cart[$key]['product']['quantity'] 	= $item['quantity'] ;
		$cart[$key]['product']['total'] 	= (( $cart[$key]['product']['is_promo'] )? $cart[$key]['product']['promo_price'] : $cart[$key]['product']['price'])*$cart[$key]['product']['quantity'] ;
		$cart_total += $cart[$key]['product']['total'];
	}
	
	//CROSS SELLING  
	$cross_selling = array();
	// $cross_selling = $app->database->query("SELECT * FROM `commerce_product_theme` WHERE `visible` = '1'ORDER BY rand() LIMIT 2 ")->fetchAll();
	// $cross_selling = $app->database->select("commerce_product_theme", "*", array( 'AND' => array( "visible" => "1" ), 'LIMIT' => '2' ) );
	// echo $app->database->last_query();
	
	
	//RENDER
	$app->render('cart.view.php', array( 
		'cart' 			=> $cart ,
		'cart_total' 	=> $cart_total ,
		// 'cross_selling' => $cross_selling ,
		'checkout_step' 	=> 1
		
	));
	
	echo "<pre>"; var_dump( $cart ); exit;
});

//******************************************************************************
//ESHOP : checkout Livraison
$app->get( '/checkout/informations', function () use ($app) 
{
	//GET RECORDED DATA
	if( isset( $_SESSION['client'] ) && ! isset($_SESSION['slim.flash']['form_data']) )
	{
		$app->flashNow('form_data', $_SESSION['client'] );
	}
	
	//SEO
	$app->view->setData('seo', array( 'title' => ($_SESSION['lang']=='fr') ? 'Informations & Livraison' : 'Informations & Delivery' )  );
	
	//RENDER
	$app->render('checkout-informations.view.php', array(
		'checkout_step' 	=> 2
	));
	
});

//---------------------------------------------------------------------
//ESHOP : checkout Livraison >> POST
$app->post( '/checkout/informations', function () use ($app) 
{

	//GET REQUEST DATA
	$params =  $app->request->post() ;
	
	// echo "<pre>"; var_dump( $data ); exit;
	
	//FORM VALIDATION
	$form_validator = ( 
		isset( $params['client_civilite'] ) && $params['client_civilite'] != "" &&
		isset( $params['client_nom'] ) && $params['client_nom'] != "" &&
		isset( $params['client_prenom'] ) && $params['client_prenom'] != "" &&
		isset( $params['client_email'] ) && $params['client_email'] != "" &&
		// isset( $params['client_tel'] ) && $params['client_tel'] != "" &&
		isset( $params['client_adresse'] ) && $params['client_adresse'] != "" &&
		isset( $params['client_cp'] ) && $params['client_cp'] != "" &&
		isset( $params['client_ville'] ) && $params['client_ville'] != "" &&
		isset( $params['client_pays'] ) && $params['client_pays'] != "" 
	);
	
	//SAVE 
	$_SESSION['client'] = $params ;
		
	if( !$form_validator )
	{
		$app->flash('error', true );
		$app->flash('form_data', $params );
		$app->redirect(URL.'/checkout/informations#error');
	}
	
		
	
	
	// echo "<pre>"; var_dump( $params );exit;
	
	
	//REDIRECT 
	$app->redirect(URL.'/checkout/commande');
});



//******************************************************************************
//ESHOP : checkout commande recap
$app->get( '/checkout/commande', function () use ($app) 
{
	//GET RECORDED DATA
	if( !isset( $_SESSION['client'] ) )
	{
		//REDIRECT 
		$app->redirect(URL.'/eshop/cart');
	}
	$app->flashNow('client', $_SESSION['client'] );
	
	//GET panier
	$cart = $_SESSION['cart'] ;
	
	//GET CART TOTAL
	$cart_total = 0;
	foreach( $cart as $key => $item )
	{
		$cart[$key]['product'] 				= $app->database->get("eshop_product" , "*", array( 'AND' => array( "id" => $item['product_id'] , "visible" => "1" ))  );
		$cart[$key]['product']['quantity'] 	= $item['quantity'] ;
		$cart[$key]['product']['total'] 	= (( $cart[$key]['product']['is_promo'] )? $cart[$key]['product']['promo_price'] : $cart[$key]['product']['price'])*$cart[$key]['product']['quantity'] ;
		$cart_total += $cart[$key]['product']['total'];
	}
	
	
	//GET CARRIERS METHOD
	$carriers = $app->database->select("eshop_carrier" , "*", array( 'AND' => array(  "visible" => "1" ) , "ORDER" => 'orden')  );
	
	//GET PAYMENT METHOD
	$payments = $app->database->select("eshop_payment" , "*", array( 'AND' => array(  "visible" => "1" ) , "ORDER" => 'orden')  );
	
	//SEO
	$app->view->setData('meta', array( 'title' => ($_SESSION['lang']=='fr') ? 'Votre commande' : 'Your order' )  );

	//RENDER
	$app->render('checkout-commande.view.php', array(
		'infos' 					=> $_SESSION['client'],
		'cart' 					=> $cart,
		'cart_total' 				=> $cart_total + $shipping_price,
		'carriers' 	=> $carriers,
		'payments' 	=> $payments,
		'checkout_step' 		=> 3
	));
	
});



//******************************************************************************
//ESHOP : checkout PAiement
$app->post( '/checkout/payment', function () use ($app) 
{
	//GET RECORDED DATA
	if( !isset( $_SESSION['client'] ) )
	{
		//REDIRECT 
		$app->redirect(URL.'/checkout/commande');
	}
	$app->flashNow('client', $_SESSION['client'] );
	$user_data =  $_SESSION['client'];
	
	//GET panier
	$cart = $_SESSION['cart'] ;
	
	//GET CART TOTAL
	$total_cart = 0;
	$order_products = '';
	foreach( $cart as $key => $item )
	{
		$cart[$key]['product'] 				= $app->database->get("eshop_product" , "*", array( 'AND' => array( "id" => $item['product_id'] , "visible" => "1" ))  );
		$cart[$key]['category'] 			= $app->database->get("eshop_category" , "*", array( 'AND' => array( "id" => $cart[$key]['product']['eshop_category_id'] ))  );
		$cart[$key]['product']['quantity'] 	= $item['quantity'] ;
		$cart[$key]['product']['price'] 	= (( $cart[$key]['product']['is_promo'] )? $cart[$key]['product']['promo_price'] : $cart[$key]['product']['price']) ;
		$cart[$key]['product']['total'] 	= $cart[$key]['product']['price'] * $cart[$key]['product']['quantity'] ;
		$total_cart += $cart[$key]['product']['total'];
		
		//format html for database
		$order_products .= $cart[$key]['product']['quantity'].' x '.$cart[$key]['category']['name'].' - '.$cart[$key]['product']['name'].' ' ;
		$order_products .= '('.$cart[$key]['product']['price'] .'€) = <b>'.$cart[$key]['product']['total'] .'€</b>';
		$order_products .= '<br />';
		
	}
	// $order_products .= '<b>TOTAL : '.$total_cart.'</b><br />';
	
	
	//GET CARRIER METHOD
	$carrier = $app->database->get("eshop_carrier" , "*", array( 'AND' => array(  "id" => $app->request->params('carrier_id') , "visible" => "1" ) , "ORDER" => 'orden')  );
	
	//GET LIVRAISON PRICE
	$total_carrier = $carrier['price'];
	
	//GET PAYMENT METHOD
	$payment = $app->database->get("eshop_payment" , "*", array( 'AND' => array( "id" => $app->request->params('payment_id') ,   "visible" => "1" ) , "ORDER" => 'orden')  );
	
	//TOTAL COMMANDE
	$total_commande = $total_cart + $total_carrier ;
	
	
	
	//SET INFORMATIONS ADDRESSES
	//insert adress in database
	$address_facturation_id = $app->database->insert('eshop_order_address' , array(
		"civilite"			=>	$user_data['client_civilite'] ,
		"nom"				=>	$user_data['client_nom'] ,
		"prenom"			=>	$user_data['client_prenom'] ,
		"email"				=>	$user_data['client_email'] ,
		"tel"				=>	$user_data['client_tel'] ,
		"adresse"			=>	$user_data['client_adresse'] ,
		"cp"				=>	$user_data['client_cp'] ,
		"ville"				=>	$user_data['client_ville'] ,
		"pays"				=>	$user_data['client_pays'] ,
		"infos"				=>	$user_data['client_infos']
	));
	
	//SET LIVRAISON IF different
	if( $user_data['livraison_different'] == "on" )
	{
		$address_livraison_id = $app->database->insert('eshop_order_address' , array(
			"civilite"			=>	$user_data['livraison_civilite'] ,
			"nom"				=>	$user_data['livraison_nom'] ,
			"prenom"			=>	$user_data['livraison_prenom'] ,
			"email"				=>	$user_data['livraison_email'] ,
			"tel"				=>	$user_data['livraison_tel'] ,
			"adresse"			=>	$user_data['livraison_adresse'] ,
			"cp"				=>	$user_data['livraison_cp'] ,
			"ville"				=>	$user_data['livraison_ville'] ,
			"pays"				=>	$user_data['livraison_pays'] ,
			"infos"				=>	$user_data['livraison_infos'] ,
		));
	
	}
	else
	{
		$address_livraison_id = $address_facturation_id ;
	}
	
	
	//CREATE ORDER
	//REFERENCE UNIQUE ID
	$reference = "C".date('ymdHis').mt_rand(0,99);			//UNIQUE ID
	$_SESSION['order_reference'] = $reference;
	
	//SAVE COMMAND IN DATABASE
	//DATABASE : INSERT COMMAND
	$order_id = $app->database->insert('eshop_order' , array(
		'date' 						=> date('Y-m-d H:i:s') ,
		'reference' 				=> $reference,
		'total' 					=> $total_commande ,
		'status' 					=> 'non payé' ,
		'products' 					=> $order_products ,
		'total_cart' 				=> $total_cart ,
		'total_carrier' 			=> $total_carrier ,
		'client_name' 				=> $user_data['client_nom'].' '.$user_data['client_prenom'] ,
		'client_email' 				=> $user_data['client_email'] ,
		'address_facturation_id' 	=> $address_facturation_id ,
		'address_livraison_id' 		=> $address_livraison_id ,
		'eshop_carrier_id' 			=> $carrier['id'] ,
		'eshop_payment_id' 			=> $payment['id'] ,
		'payment_code' 				=> '' ,
		'archived' 					=> 0 
	));
	
	
	//CREATE ORDER_PRODUCTS
	foreach( $cart as $key => $item )
	{
		//SAVE ORDER_PRODUCT IN DATABASE
		$app->database->insert('eshop_order_product' , array(
			'ref' 					=> $item['product']['ref'] ,
			'name' 					=> $item['product']['name'] ,
			'quantity' 				=> $item['product']['quantity'] ,
			'price' 				=> $item['product']['price'] ,
			'is_promo' 				=> $item['product']['is_promo'] ,
			'weight' 				=> $item['product']['weight'] ,
			'eshop_order_id' 		=> $order_id
		));
	
	}
	//-------------------------------------------------------------------------------------------
	
	
	
	// echo "<hr /><pre>".var_dump( $order_id )."</pre><hr />";
	// exit;
	
	$api = strtolower($payment['name']) ; 
	$payment_config = $app->$api ; 
	
	
	
	//RENDER
	$app->render('checkout-paiement.view.php', array(
		'cart' 				=> $cart,
		'total_commande' 	=> $total_commande,
		'total_cart' 		=> $total_cart,
		'total_carrier' 	=> $total_carrier,
		'reference' 		=> $reference,
		'user_data' 		=> $user_data,
		'payment' 			=> strtolower($payment['name']),
		'payment_config' 	=> $payment_config,
		'checkout_step' 	=> 4
	));
	
	
});


//******************************************************************************
//ESHOP : checkout MERCI
$app->map( '/checkout/merci', function () use ($app) 
{
	//GET RECORDED DATA
	if( !isset( $_SESSION['client'] ) )
	{
		//REDIRECT 
		// $app->redirect(URL);
	}
	$app->flashNow('client', $_SESSION['client'] );
	$user_data =  $_SESSION['client'];
	$reference =  $_SESSION['order_reference'];
	
	//UNSET PANIER
	unset($_SESSION['cart']);
	unset($_SESSION['order_reference']);
	
	//SEO
	$app->view->setData('seo', array( 'title' => ($_SESSION['lang']=='fr') ? 'Merci' : 'Thank you' )  );
	
	
	//RENDER
	$app->render('checkout-merci.view.php', array(
		'checkout_step' 	=> 5 , 
		'reference'		=> $reference
	));
	
})->via('GET', 'POST');

//******************************************************************************
//ESHOP : checkout Error
$app->map( '/checkout/erreur', function () use ($app) 
{
	//GET RECORDED DATA
	if( !isset( $_SESSION['client'] ) )
	{
		//REDIRECT 
		// $app->redirect(URL);
	}
	$app->flashNow('client', $_SESSION['client'] );
	$user_data =  $_SESSION['client'];
	
	//GET panier
	$cart = $_SESSION['cart'] ;
	$cart_total = 0;
	$cart_theme_count = 0;
	$reference =  $_SESSION['order_reference'];
	
	//UPDATE COMMAND
	$commande = $app->database->update('commerce_commande', array( "status" => "annulé"  ) , array( "reference" => $reference  )  );
	
	//UNSET REFERENCE
	unset($_SESSION['order_reference']);
	
	//SEO
	$app->view->setData('seo', array( 'title' => ($_SESSION['lang']=='fr') ? 'Annulation' : 'Order canceled' )  );
	
	//RENDER
	$app->render('checkout-error.view.php', array(
		'checkout_step' 	=> 5
	));
	
})->via('GET', 'POST');

//******************************************************************************
// TEST CONFIRMATION EMAIL
/*
$app->get( '/checkout/test-confirmation', function () use ($app)
{
	$reference = "C15011814112677";
	
	//GET ORDER BY REF
	$paypal_checked_commande = $app->database->get('eshop_order' , "*", array( 'AND' => array( "reference" => $reference )  ) ) ;
	//GET addresses
	$paypal_checked_commande['address_facturation'] = $app->database->get('eshop_order_address' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['address_facturation_id'] )  ) ) ;
	$paypal_checked_commande['address_livraison'] 	= $app->database->get('eshop_order_address' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['address_livraison_id'] )  ) ) ;
	//GET carrier method
	$paypal_checked_commande['carrier'] 			= $app->database->get('eshop_carrier' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['eshop_carrier_id'] )  ) ) ;
	//GET payment method
	$paypal_checked_commande['payment'] 			= $app->database->get('eshop_payment' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['eshop_payment_id'] )  ) ) ;
	
	
	//SEND CONFIRMATION
	echo "CONFIRMATION";
	
	//SEND MAIL TO 
	//MAIL TO ?
	$app->email->to( $paypal_checked_commande['client_email'] );
	$app->email->bcc( ESHOP_MAILTO   );
	// $app->email->reply_to( $paypal_checked_commande['client_email'] , $paypal_checked_commande['client_nom']." ".$paypal_checked_commande['client_prenom'] );
	
	//SET MESSAGE
	$email_content = $app->view()->fetch('payment/email-confirmation.view.php', array(
		'order' => $paypal_checked_commande,
	) );;
	
	//SEND EMAIL
	$app->email->subject( "MOTMOTBIJOUX > Confirmation de commande  ".$reference );
	$app->email->message( $email_content );

	//SEND MAIL
	//envoi du mail 
	$app->email->send();
	
	//DEBUGG MAIL
	echo $email_content; 	
	echo $app->email->print_debugger();

});
*/

//******************************************************************************
//******************************************************************************
//******************************************************************************
//******************************************************************************
// PAYPAL IPN CHECKOUT
$app->map( '/paypal/confirmation/m07m0781j0ux', function () use ($app)
{
	
	$chaine = ''; 
	$reponse = '';
	$donnees = '';
  
	$url = parse_url($app->paypal->ipn_serveur);        
	$port = $app->paypal->port;        
	
	// echo( $url[scheme]."://".$url[host] ); exit; 
	// var_dump( $url ); exit; 
	
	
	// foreach ($_POST as $champs=>$valeur) 
	foreach ( $app->request->params() as $champs=>$valeur) 
	{ 
		$donnes["$champs"] = $valeur;
		$chaine .= $champs.'='.urlencode(stripslashes($valeur)).'&'; 
	}
	$chaine.="cmd=_notify-validate";
	
	
	# Chemin vers fichier texte
	$file ="assets/paypal.txt";
	# Ouverture en mode écriture
	$fileopen=(fopen("$file",'a'));
	# Ecriture de "Début du fichier" dansle fichier texte
	fwrite($fileopen, $chaine."\n");
	# On ferme le fichier proprement
	fclose($fileopen);
	
	
	// open the connection to paypal
	// $fp = fsockopen( $url[host] , "80" ,$err_num,$err_str,30); 
	// $fp = fsockopen('ssl://www.sandbox.paypal.com', 443, $errno, $errstr, 30);
	$fp = fsockopen ( $url[scheme]."://".$url[host] , $port , $errno, $errstr, 30);
	if(!$fp) 
	{
		// echo "ERROR HOST";
		return false;
	} 
	else 
	{ 
		
		fputs($fp, "POST $url[path] HTTP/1.1\r\n"); 
		fputs($fp, "Host: $url[host]\r\n"); 
		fputs($fp, "Content-type: application/x-www-form-urlencoded\r\n"); 
		fputs($fp, "Content-length: ".strlen($chaine)."\r\n"); 
		fputs($fp, "Connection: close\r\n\r\n"); 
		fputs($fp, $chaine . "\r\n\r\n"); 

		while(!feof($fp))  
			$reponse .= fgets($fp, 1024); 

		fclose($fp); 

	}

	if(strstr($reponse, "VERIFIED"))
	{
		$reference = $app->request->params('invoice');
		
		//SECURITY CHECKS
		//txn_id UNIQ
		$txn_id = $app->request->params('txn_id');
		$paypal_check_txn_id = $app->database->select('eshop_order' , array( "payment_code" => $txn_id )  );
		
		//receiver_email VALID
		$receiver_email = $app->request->params('receiver_email');
		$paypal_check_receiver_email = ( $receiver_email == $app->paypal->compte );
		
		//payment_status = Completed
		$payment_status = $app->request->params('payment_status');
		$paypal_check_payment_status = $payment_status == "Completed" ;
		
		//Price = price
		$mc_gross = $app->request->params('mc_gross');
		$mc_shipping1 = $app->request->params('mc_shipping1');
		
		//GET ORDER BY REF
		$paypal_checked_commande = $app->database->get('eshop_order' , "*", array( 'AND' => array( "reference" => $reference )  ) ) ;
		//GET addresses
		$paypal_checked_commande['address_facturation'] = $app->database->get('eshop_order_address' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['address_facturation_id'] )  ) ) ;
		$paypal_checked_commande['address_livraison'] 	= $app->database->get('eshop_order_address' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['address_livraison_id'] )  ) ) ;
		//GET carrier method
		$paypal_checked_commande['carrier'] 			= $app->database->get('eshop_carrier' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['eshop_carrier_id'] )  ) ) ;
		//GET payment method
		$paypal_checked_commande['payment'] 			= $app->database->get('eshop_payment' , "*", array( 'AND' => array( "id" => $paypal_checked_commande['eshop_payment_id'] )  ) ) ;
		
		
		//CHECK IF PRICE == REF PRICE
		$paypal_checked_commande_price  = ( isset( $paypal_checked_commande['total']) AND ( floatval ($paypal_checked_commande['total']) == ($mc_gross)) ) ;
		
		
		if( $paypal_check_receiver_email && $paypal_check_payment_status && $paypal_checked_commande_price )
		{
			//UPDATE COMMAND
			$commande = $app->database->update('eshop_order' , array( "status" => "payé" , "payment_code" => $txn_id) , array( "reference" => $reference  )  );
			
			//SEND CONFIRMATION
			echo "CONFIRMATION";
			
			//SEND MAIL TO 
			//MAIL TO ?
			$app->email->to( $paypal_checked_commande['client_email'] );
			$app->email->bcc( ESHOP_MAILTO  );
			// $app->email->reply_to( $paypal_checked_commande['client_email'] , $paypal_checked_commande['client_nom']." ".$paypal_checked_commande['client_prenom'] );
			
			//SET MESSAGE
			$email_content = $app->view()->fetch('payment/email-confirmation.view.php', array(
				'order' => $paypal_checked_commande,
			) );;
			
			//SEND EMAIL
			$app->email->subject( "MOTMOTBIJOUX > Confirmation de commande  ".$reference );
			$app->email->message( $email_content );

			//SEND MAIL
			//envoi du mail 
			$app->email->send();
			
			//DEBUGG MAIL
			// echo $email_content; 	
			// echo $app->email->print_debugger();
			
			//UNSET SESSION email
			unset( $_SESSION['email'] );
			
		}
		else
		{
			//UPDATE COMMAND ERROR
			$commande = $app->database->update('eshop_order' , array( "status" => "error" ) , array( "reference" => $reference  )  );
			
			//SEND ERROR
			echo "ERROR";
		}
		
		
	}
	else
	{
		echo "CANCEL";
		
		$reference = $app->request->params('invoice');
		$txn_id = $app->request->params('txn_id');
		
		//UPDATE COMMAND
		$commande = $app->database->update('eshop_order', array( "status" => "annulé" , "payment_code" => $txn_id ) , array( "reference" => $reference  )  );
		
		
	}

	

})->via('GET', 'POST');

//******************************************************************************
// PAYBOX IPN CHECKOUT
$app->map( '/paybox/confirmation/m07m0781j0ux', function () use ($app)
{
	
	$chaine = ''; 
	$reponse = '';
	$donnees = '';
	
	
	// foreach ($_POST as $champs=>$valeur) 
	foreach ( $app->request->params() as $champs=>$valeur) 
	{ 
		$donnes["$champs"] = $valeur;
		$chaine .= $champs.'='.urlencode(stripslashes($valeur)).'&'; 
	}
	// $chaine.="cmd=_notify-validate";
	$chaine.="...IP=".$_SERVER['REMOTE_ADDR'];
	
	//CHECK IF IPN IP == OK
	$checked_ip = 0;
	foreach( $app->paybox->ip_ipn as $ip )
	{	
		if( $ip == $_SERVER['REMOTE_ADDR'] )
		{
			$checked_ip = true;
			continue;
		}
	}
	$chaine.="...CHECK=".$checked_ip;
	

	//CODES ERRORS PAYBOX
	$tabError = array(
		'00000' => '',
		'00001' => 'La connexion au centre d’autorisation a échoué. Vous pouvez dans ce cas là effectuer les redirections des internautes vers le FQDN tpeweb1.paybox.com.',
		'001xx' => 'Paiement refusé par le centre d’autorisation',
		'00003' => 'Erreur Paybox',
		'00004' => 'Numéro de porteur ou cryptogramme visuel invalide.',
		'00006' => 'Accès refusé ou site/rang/identifiant incorrect.',
		'00008' => 'Date de fin de validité incorrecte',
		'00009' => 'Erreur de création d’un abonnement.',
		'00010' => 'Devise inconnue.',
		'00011' => 'Montant incorrect.',
		'00015' => 'Paiement déjà effectué.',
		'00016' => 'Abonné déjà existant (inscription nouvel abonné). Valeur ‘U’ de la variable PBX_RETOUR.',
		'00021' => 'Carte non autorisée.',
		'00029' => 'Carte non conforme. Code erreur renvoyé lors de la documentation de la variable « PBX_EMPREINTE ».',
		'00030' => 'Temps d’attente > 15 mn par l’internaute/acheteur au niveau de la page de paiements.',
		'00031' => 'Code réservé par paybox',
		'00032' => 'Code réservé par paybox',
		'00033' => 'Code pays de l’adresse IP du navigateur de l’acheteur non autorisé.',
		'00040' => 'Opération sans authentification 3DSecure, bloquée par le filtre.'
	);
	
	# Chemin vers fichier texte
	$file ="assets/paybox.txt";
	# Ouverture en mode écriture
	$fileopen=(fopen("$file",'a'));
	# Ecriture de "Début du fichier" dansle fichier texte
	fwrite($fileopen, $chaine."\n");
	# On ferme le fichier proprement
	fclose($fileopen);
	
	
	//GET ERROR CODE
	$error_code = $app->request->params('erreur');
	
	if( $checked_ip && $error_code == "00000") 
	{
		$reference = $app->request->params('ref');
		
		//SECURITY CHECKS
		//transaction_id UNIQ
		$transaction_id = $app->request->params('trans');
		$checked_transaction_id = $app->database->select('eshop_order' , array( "payment_code" => $transaction_id )  );
		
		//payment_status = Completed
		// $payment_status = $app->request->params('payment_status');
		
		//Price = price
		$montant = $app->request->params('montant');
		

		//GET ORDER BY REF
		$checked_commande = $app->database->get('eshop_order' , "*", array( 'AND' => array( "reference" => $reference )  ) ) ;
		//GET addresses
		$checked_commande['address_facturation'] = $app->database->get('eshop_order_address' , "*", array( 'AND' => array( "id" => $checked_commande['address_facturation_id'] )  ) ) ;
		$checked_commande['address_livraison'] 	= $app->database->get('eshop_order_address' , "*", array( 'AND' => array( "id" => $checked_commande['address_livraison_id'] )  ) ) ;
		//GET carrier method
		$checked_commande['carrier'] 			= $app->database->get('eshop_carrier' , "*", array( 'AND' => array( "id" => $checked_commande['eshop_carrier_id'] )  ) ) ;
		//GET payment method
		$checked_commande['payment'] 			= $app->database->get('eshop_payment' , "*", array( 'AND' => array( "id" => $checked_commande['eshop_payment_id'] )  ) ) ;
		
		
		//CHECK IF PRICE == REF PRICE
		$checked_commande_price  = ( isset( $checked_commande['total']) AND ( floatval ($checked_commande['total']) == floatval($montant/100)) ) ;
		
		
		if( !$checked_transaction_id && $checked_commande_price )
		{
			//UPDATE COMMAND
			$commande = $app->database->update('eshop_order' , array( "status" => "payé" , "payment_code" => $transaction_id ) , array( "reference" => $reference  )  );
			
			//SEND CONFIRMATION
			echo "CONFIRMATION";
			
			//SEND MAIL TO 
			//MAIL TO ?
			$app->email->to( $checked_commande['client_email'] );
			$app->email->bcc( ESHOP_MAILTO  );
			// $app->email->reply_to( $checked_commande['client_email'] , $checked_commande['client_nom']." ".$checked_commande['client_prenom'] );
			
			//SET MESSAGE
			$email_content = $app->view()->fetch('payment/email-confirmation.view.php', array(
				'order' => $checked_commande,
			) );;
			
			//SEND EMAIL
			$app->email->subject( "MOTMOTBIJOUX > Confirmation de commande  ".$reference );
			$app->email->message( $email_content );

			//SEND MAIL
			//envoi du mail 
			$app->email->send();
			
			//DEBUGG MAIL
			// echo $email_content; 	
			// echo $app->email->print_debugger();
			
			//UNSET SESSION email
			unset( $_SESSION['email'] );
			
		}
		else
		{
			//UPDATE COMMAND ERROR
			$commande = $app->database->update('eshop_order' , array( "status" => "annulé" , "payment_code" => $transaction_id." error : (price:".$checked_commande_price.'€)' ) , array( "reference" => $reference  )  );
			
			//SEND ERROR
			echo "ERROR";
		}
		
		
	}
	else
	{
		echo "ERROR";
		
		$reference = $app->request->params('ref');
		$transaction_id = $app->request->params('trans');
		
		//UPDATE COMMAND
		$commande = $app->database->update('eshop_order', array( "status" => "error" , "payment_code" => $transaction_id." error : ".$error_code.'='.$tabError[$error_code] ) , array( "reference" => $reference  )  );
		
		
	}

	

})->via('GET', 'POST');







?>
