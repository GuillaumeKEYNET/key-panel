<?php

//******************************************************************************
//SET LOCALES
date_default_timezone_set('Europe/Paris');
setlocale (LC_TIME, 'fr_FR.utf8','fra'); 
//******************************************************************************
//SET SLIM & ORM
require '../Slim/Slim.php';
require '../Slim/lib/medoo.min.php';
\Slim\Slim::registerAutoloader();

//******************************************************************************
$app = new \Slim\Slim(array(
    'templates.path' => './views' 
));
$app->add(new \Slim\Middleware\SessionCookie(array('expires' => '120 minutes')));
$app->add(new \Slim\Middleware\Flash);
//******************************************************************************
require 'config.php';
require 'fields/.field.php';
require 'custom.php';
//******************************************************************************
// INDEx
$app->get('/', function () use ($app) {
   
   //REDIRECT
   $app->redirect( URL.APP_DEFAULT  );
   
});

//******************************************************************************
//Afficher > liste > GET/ $
$app->get( '/show/(:what)', function ($what) use ($app) {
	
	//GET setup from json
	$table = json_get( "./setup/".$what.".json" );
	
	//404
	if( !$table ) { $app->notFound(); exit; }
	
	// dump( $table );
	
	//QUERY FROM DATABASE
	$params = array();
	if( isset($table['where']) && $table['where'] ) 		$params['AND'] = $table['where'];
	if( isset($table['order']) && $table['order'] ) 		$params['ORDER'] = $table['order'];
	$data = $app->database->select( $table['table'] ,  "*" , $params  );

	// dump( $app->database->last_query() );
	
	//RENDER
	$app->render('list.view.php', array(
		'table' => $table,
		'data' => $data,
	) );
	
	
	
});

//******************************************************************************
//Afficher > item > GET/ $ / $id
$app->get( '/show/(:what)/(:id)', function ($what , $id ) use ($app) {
	
	//GET setup from json
	$table = json_get( "./setup/".$what.".json" );
	
	//404
	if( !$table ) { $app->notFound(); exit; }
	
	//QUERY FROM DATABASE
	$data = $app->database->get( $table['table'] ,  "*" , array( 'AND' => array( 'id' =>  $id )  )  );
	
	
	//---------------------------------------------------
	//CHILD TABLE
	$table_child = array();
	$data_child = array();
	if( $data && @$table['child']  )
	{
		$table_child = json_get( "./setup/".$table['child'].".json" );
		
		//404
		if( !$table_child ) { $app->notFound(); exit; }
		
		//QUERY FROM DATABASE
		$params = array();
		if( isset($table_child['where']) && $table_child['where'] ) 		$params['AND'] = $table_child['where'];
		if( isset($table_child['order']) && $table_child['order'] ) 		$params['ORDER'] = $table_child['order'];
		
		//ID PARENT
		// $params['AND'][$table['table']] = $id;
		$params['AND'][$table_child['parent_id_field']] = $id;
		
		$data_child = $app->database->select( $table_child['table'] ,  "*" , $params  );
		
	}
	//---------------------------------------------------
	//PARENT TABLE ?
	if( $data && @$table['parent'] )
	{
		$data['parent_id'] = @$data[$table['parent_id_field']] ; 
	}
	elseif( @$table['parent'] )
	{
		//ADD CHILD TO PARENT
		$data['parent_id'] = $app->request->params('parent_id') ;
		$data[$table['parent_id_field']] = $app->request->params('parent_id') ;
	}
	//---------------------------------------------------
	
	//RENDER
	$app->render('item.view.php', array(
		'table' => $table,
		'data' => $data,
		
		'table_child' => $table_child,
		'data_child' => $data_child,
		
		
	) );
	
});

//******************************************************************************
//update > item > POST/ $ / $id
$app->post( '/update/(:what)/(:id)', function ($what , $id = "add" ) use ($app) {
	
	//GET setup from json
	$table = json_get( "./setup/".$what.".json" );
	
	//404
	if( !$table ) { $app->notFound(); exit; }
	
	//PREPARE INSERT DATA
	$data = array();
	
	//GET PARAMS & FIELDS
	foreach( $table['fields'] as $field ) 
	{
		$object = new $field['type'](array(
			'fieldname' => 	@$field['name'] ,
			'value' 	=> 	$app->request->params($field['name']) ,
		))  ; 
		
		$data[$field['name']] = $object->get_processed();
		
		//IMAGE NO MODIFICATIONS ?
		if( $field['type'] == "file_img" && $data[$field['name']] == '' )
			unset( $data[$field['name']] );
	
	}
	
	
	
	//QUERY FROM DATABASE
	if( $id == "add" )
		//INSERT
		$app->database->insert( $table['table'] ,  $data  );
	else
		//UPDATE
		$app->database->update( $table['table'] ,  $data , array( 'id' =>  $id ) );
	
	//FLASH DATA
	$app->flash('update', true );
	// $app->flash('form_data', $_POST );
	
	// dump( $app->database->last_query() );exit;
	
	if( @$table['parent'] )
		$app->redirect(URL.'/show/'.$table['parent'].'/'.$data[$table['parent_id_field']]."#list_children" );
	else
		$app->redirect(URL.'/show/'.$what);
	
});
//******************************************************************************

//******************************************************************************
//update > item > POST/ $ / $id
$app->post( '/update-field/(:what)/(:id)', function ($what , $id = "add" ) use ($app) {
	
	$table = $what;
	
	//404
	if( !$table ) { $app->notFound(); exit; }
	
	//PREPARE INSERT DATA
	$data = array();
	$data = $app->request->params();
	
	// dump( $data );
	
	//QUERY FROM DATABASE
	//UPDATE
	$output = $app->database->update( $table ,  $data , array( 'id' =>  $id ) );
	
	dump( $output );
	
	
	
}); 

//******************************************************************************
//IMAGE delete > ?$_GET  : file_img = 
$app->get( '/remove-image', function ( ) use ($app) {
	
	//GET FILE NAME
	$file_img = $app->request->params( 'file_img' );
	
	//SET RELATIVE UPLOAD PATH
	$relative_path = RELATIVE_PATH."/".PATH."/img"; 
	
	//DELETES FILES (exept Raw)
	unlink( $relative_path.'/'.$file_img);
	unlink( $relative_path.'/thumbs/'.$file_img );
	unlink( $relative_path.'/mids/'.$file_img );
	
	dump( $file_img );
	
}); 

//******************************************************************************
//DELETE > item > POST/ $ / $id
$app->get( '/delete/(:what)/(:id)', 'delete_item' );
$app->delete( '/delete/(:what)/(:id)', 'delete_item' );
function delete_item( $what , $id ) {
	
	global $app;
	
	//GET setup from json
	$table = json_get( "./setup/".$what.".json" );
	
	//404
	if( !$table ) { $app->notFound(); exit; }
	
	//QUERY FROM DATABASE
	//DEKETE
	$output = $app->database->delete( $table['table'] ,  array( 'id' =>  $id ) );
	
	//FLASH DATA
	$app->flash('delete', true );
	$app->redirect(URL.'/show/'.$what);
	
}; 



//******************************************************************************
//UPLOAD
$app->post( '/upload/image', function () use ($app) 
{
    //SET RELATIVE UPLOAD PATH
	$relative_path = RELATIVE_PATH."/".PATH."/img"; 
	$image_path = URL."/".PATH."/img"; 
	
	
	//GET PARAMS
	if (!isset($_FILES['uploads'])) {
        echo "No files selected !!";
        return;
    }
	$file = $_FILES['uploads'];
   
	//UPLOAD & MOVE & RENAME
	if ($file['error'] === 0) 
	{
		//MOVE UPLOADED FILE TO PATH
		$name = pathinfo( $file['name'], PATHINFO_FILENAME ).'-'.(date('ymd-His')).".".pathinfo( $file['name'], PATHINFO_EXTENSION); ;
		$move_ok = move_uploaded_file( $file['tmp_name'] ,  $relative_path."/".$name );
		
		if ( $move_ok === true) 
		{
			echo  $image_path."/".$name ;
		}
		else
		{
			echo 'ERROR UPLOAD !!';
		}

	}
    
	exit;

});

//******************************************************************************
//CONNEXION
$app->post( '/connexion', function () use ($app) 
{
	//GET PARAMS
	$login 	= $app->request->post('login'); 
	$sesame = $app->request->post('sesame'); 
	
	//GET USERS from json
	$users = json_get( "./setup/.users.json" );
	$verified_user = false;
	foreach( $users as $user )
	{
		if( $user['login'] == $login   &&   $user['sesame'] == md5(APP_SECRET.'**'.$sesame) )
		{
			$verified_user = $user;
			break;
		}
	}
	
	
	if( $verified_user )
	{
		$_SESSION['user'] = $verified_user ;
		//FLASH
		$app->flash('info', "Vous voilà bien connecté" );
	}
	else
	{
		$_SESSION['user'] = false;
		//FLASH
		$app->flash('error', "Wrong IDs" );
	}
	
	$app->redirect( URL.'/');	
});
//******************************************************************************
//DeCONNEXION
$app->get( '/deconnexion', function () use ($app) 
{
	$_SESSION['user'] = false;
	unset( $_SESSION['user'] );
	
	$app->redirect( URL.'/');	
});
//******************************************************************************
//CONNEXION HOOK 
$app->hook('slim.before', function ()  use ($app) 
{
    //CHECK CONNEXION
	$connected =  ( isset($_SESSION['user']) && $_SESSION['user'] );
	if( !$connected && ($app->request->getResourceUri() != '/connexion' &&  $app->request->getResourceUri() != '/install' ))
	{
		if( $app->request->getResourceUri() != '/' )
			$app->redirect( URL.'/');
		
		//RENDER
		$app->render('connexion.view.php' );
		exit;
	}
	
	//GET MENU
	$menu = json_get( "./setup/.menu.json" );
	$app->view->setData('menu', $menu );
	// echo "<pre>";
	// var_dump( $menu  ) ; exit;
	
});

//******************************************************************************
//AUTOMATIC INSTALLATION
$app->get( '/install', function ( ) use ($app) 
{
	
	//DETECT SETUP FILES
	$setup_files = preg_grep('/^([^.])/', scandir( "./setup" ));
	
	//DROP PARAM
	$drop = $app->request->params('drop');
	
	$output ="";
	//GENERATE MYSQL CREATE TABLES
	foreach( $setup_files as $setup_file )
	{
		$table = json_get( "./setup/".$setup_file );
		echo ( $setup_file . ' --> ' .$table['table'] ." : ". @$table['bdd_action'] .' <br />'  );
		
		$BDD_ACTION = ( @$table['bdd_action'] == "create"  ) ;
		
		if( $drop && APP_ERASE == true && @$BDD_ACTION )
		{
			//DROP TABLE !
			$query = "DROP TABLE IF EXISTS `".$table['table']."` ; "; 
			$ok = $app->database->query( $query );
			
			$output .= "<h2>".$table['table']."</h2>";
			$output .= $query;
			$output .= "<br />";
			$output .= "<b>".(($ok)?'QUERY OK':'ERROR QUERY !!!!')."</b>";
			$output .= "<br />";
		}
		elseif( !$drop && APP_INSTALL == true && @$BDD_ACTION )
		{
			
			//CREATE TABLE !
			$query = "
	CREATE TABLE IF NOT EXISTS `".$table['table']."` (
	`id` int(10) unsigned NOT NULL AUTO_INCREMENT,";
			
			//FIELDS
			foreach( $table['fields'] as $field )
			{
				$query .= "
	`".$field['name']."` ".$field['db_type']." DEFAULT NULL,";
			}
			
			//SORTABLE >> ORDEN
			if( @$table['sortable'] == true )
			{
				$query .= "
	`orden` int DEFAULT NULL,";
			}
			
			//ID PRIMARY KEY
			$query .= "
	PRIMARY KEY (`id`)
	) CHARSET=utf8 COLLATE=utf8_unicode_ci ;";
			
			$ok = $app->database->query( $query );
			
			$output .= "<h2>".$table['table']."</h2>";
			$output .= $query;
			$output .= "<br />";
			$output .= "<b>".(($ok)?'QUERY OK':'ERROR QUERY !!!!')."</b>";
			 
		}
		else
		{
			$output .= "<h2>".$table['table']."</h2>";
			$output .= "NO QUERY<br />";
		}
		$output .= "<hr />";
		
		
		
	
		
	
	}

	
	//GET USERS JSON
	$users = json_get( "./setup/.users.json" );
	
	//GENERATE MD5 PASSWORDS
	foreach( $users as $key => $user )
	{
		if( isset( $user['password'] ) &&  $users[$key]['password'] != "" )
		{
			$users[$key]['sesame'] =  md5( APP_SECRET."**".$user['password'] );
			$users[$key]['password'] = "";
		}
	}
	
	
	//WRITE JSON ON .users.json
	file_put_contents( "./setup/.users.json" ,  json_encode($users, JSON_PRETTY_PRINT) );

	
	//FLASH
	$app->flash('info', "INSTALL OK <hr />USERS passwords encrypteds<hr />DATABASE queries : <br />".$output );

	echo "<hr />INSTALL OK <hr />USERS passwords encrypteds<hr />DATABASE queries : <br />".$output ; exit; 

		
	//REDIRECT
	$app->redirect( URL.'/');	
	
});


//******************************************************************************
//404
$app->notFound(function () use ($app) {
  
	echo ("//ERROR 404"); exit;
	//RENDER 404
	$app->render('404.view.php' , array(  )  , 404 );
});
//******************************************************************************
$app->run();



/*
	$app->users = json_get( "./setup/_users.json" );
*/
//******************************************************************************
function json_get( $file )
{
	return json_decode(file_get_contents($file), true  , 12);
}
//******************************************************************************
function dump( $data )
{
	echo "<pre>"; 
	var_dump( $data ) ;
	exit;
}
