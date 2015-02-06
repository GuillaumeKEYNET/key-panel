<?php

//******************************************************************************
//SET SLIM & ORM
require 'Slim/Slim.php';
require 'Slim/lib/medoo.min.php';
require 'Slim/lib/Email.php';

\Slim\Slim::registerAutoloader();

//******************************************************************************
$app = new \Slim\Slim(array(
    'templates.path' => './views'
));

//INIT SESSIONS & COOKIES
$app->add(new \Slim\Middleware\SessionCookie);
$app->add(new \Slim\Middleware\Flash);
//******************************************************************************
//GET CONFIG
require 'config.php';

//******************************************************************************
//SET ROUTES
// require 'routes/blog.route.php'; 
require 'eboutique.php';

//******************************************************************************
//HOME
$app->get( '/', function () use ($app) 
{
	//GET SLIDER IMAGES
	$slideshow = $app->database->query( "SELECT * FROM slideshow WHERE visible = 1 ORDER BY orden" )->fetchAll();
	
	//GET ALL PRODUCTS
	$products = $app->database->query( "SELECT * FROM eshop_product WHERE visible = 1 ORDER BY orden" )->fetchAll();
	foreach( $products as $key => $item )
	{
		//GET CATEGORY BY PRODUCT
		$products[$key]['category'] = $app->database->get( 'eshop_category' , '*' , array( "id" => $item['eshop_category_id'] ) );
		
		//SET URL
		$products[$key]['url'] = URL.'/eshop-'.$products[$key]['category']['slug'].'/'.$item['id'].'~'.$item['slug'] ;
	}
	
	//METAS
	$meta = array(
		'title' => '' ,
		'description' => '' ,
		'url' => '/' ,
	);
	
	 
	// RENDER
	$app->render('home.view.php', array(
		'slideshow' => $slideshow,
		'products' => $products,
		'meta' => $meta,
	) );
	// $app->view()->fetch();
		
});


//******************************************************************************
//PAGES
$app->get( '/(:page_slug)', function ( $page_slug ) use ($app) 
{
	//GET ACTUS
	$page = $app->database->get("page", "*", array( "AND" => array( "slug" => $page_slug , "visible" => "1"  ) ) );
	
	// var_dump( $page );exit;
	
	//404
	if( !$page ) { $app->notFound(); exit; }
	
	//METAS
	$meta = array(
		'title' => $page['title'].' - ' ,
		'description' => $page['title'] ,
		'url' => '/'.$page_slug ,
	);
	
	//RENDER
	$app->render('page.view.php', array(
		'meta' => $meta,
		'page' => $page,
	
	) );
		
});


//------------------------------------------------------------------------
//contact
$app->get( '/contact', function () use ($app) 
{
	//GET TEXT page
	$page = $app->database->get('page_formulaire' , '*', array( 'id' => 2 ) );
	
	//SEO
	$app->view->setData('seo', array( 'title' => 'Contact' )  );

	
	//RENDER
	$app->render('contact.view.php', array( 
		'page' => $page 
	) );
	
});

//------------------------------------------------------------------------
//contact
$app->post( '/contact/send', function () use ($app) 
{
	// $contact_object 	= $app->request->params('object');
	$contact_name 		= $app->request->params('nom');
	$contact_email 		= $app->request->params('email');
	$contact_message 	= $app->request->params('message');
	
	
	//FORM VALIDATION
	$form_validator = ( 
		// isset( $contact_object ) && $contact_object != "" &&
		isset( $contact_name ) && $contact_name != "" &&
		isset( $contact_email ) && $contact_email != "" &&
		isset( $contact_message ) && $contact_message != ""
	);
	if( !$form_validator )
	{
		$app->flash('error', true );
		$app->flash('form_data', $app->request->params() );
		$app->redirect(URL.'/contact');
	}
	
	//SEND MAIL //SEND MAIL TO 
	//MAIL TO ?
	$app->email->to( 'nina.joffe@outlook.fr , nina.joffe@milieuduciel.eu' );
	$app->email->reply_to( $contact_email , $contact_name );
	
	//SET MESSAGE
	$email_content = "
	<h3 style='font-size: 16px; font-family: times, serif; color: #000; '>MILIEU DU CIEL >> Contact  >> ".$contact_name."</h3>
	<br />
	<b>NOM :</b> ".$contact_name." <br />
	<b>Email :</b> ".$contact_email ." <br /><br />
	<b>coordonnees :</b> <br />".nl2br(strip_tags($contact_message))." <br />

	";
	//SEND EMAIL
	$app->email->subject( "MILIEU DU CIEL >> Contact  >> ".$contact_name );
	$app->email->message( $email_content );

	//SEND MAIL
	//envoi du mail 
	$app->email->send();
	
	//DEBUGG MAIL
	// echo $email_content; 	
	// echo $app->email->print_debugger();
	
	// exit;	
	//UNSET SESSION email
	unset( $_SESSION['email'] );
	
	$app->flash('success', true );
	//REDIRECT 
	$app->redirect(URL.'/contact');
	
	
});



//******************************************************************************
//404
$app->notFound(function () use ($app) {
  
	// echo ("//ERROR 404"); exit;
	//RENDER 404
	$app->render('404.view.php' , array(  )  , 404 );
});
//******************************************************************************


//******************************************************************************
//GET GLOBAL CONTENT
//CART INIT
//LANG DETECT
$app->hook('slim.before', function () use ($app) {

	//GET LANG
	if(  isset($_GET['lang']) )
		$_SESSION['lang'] =  $_GET['lang'] ;
	elseif(  isset($_SESSION['lang']) )
		$_SESSION['lang'] =  $_SESSION['lang'] ;
	else
		$_SESSION['lang'] = 'fr' ;
		
	$app->view->setData('lang', $_SESSION['lang'] );
	
	//GET MENU (project_types)
	// $menus = $app->database->select("project_type", "*", array( 'ORDER' => 'orden ' )  );
	// $app->view->setData('menus', $menus );
	
	//PANIER init
	if(  !isset($_SESSION['cart']) )
		$_SESSION['cart'] =  array() ;
		
	$app->view->setData('cart', $_SESSION['cart']  );
	
});


//******************************************************************************
// post put delete patch
$app->post('/post',function () {
	echo 'This is a POST route';
});

//******************************************************************************
$app->run();

function slug($string){
   $slug=preg_replace('/[^A-Za-z0-9-]+/', '', $string);
   return $slug;
}

