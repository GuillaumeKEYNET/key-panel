<?php

//******************************************************************************
// DASHBOARD
$app->get('/dashboard', function () use ($app) {
   
	//RENDER
	$app->render('dashboard.view.php', array(
		// 'welcome_text' => $welcome_text,
		// 'project' => $project,
		// 'meta' => $meta,
	) );
		
   
});
//******************************************************************************
// CREATE THUMBS
$app->get('/thumbs', function () use ($app) {
   
   $imageClass = new file_img( array() );
	
	//SET RELATIVE UPLOAD PATH
	$relative_path = RELATIVE_PATH."/".PATH."/img"; 
	$image_path = URL."/".PATH."/img"; 
	
	
	$dir    = $relative_path ;
	$files = scandir($dir);
	
	// var_dump( $files );exit;
	foreach( $files as $file_new_name )
	{
	
		if( is_file( $relative_path.'/'.$file_new_name ) && !is_file( $relative_path.'/thumbs/'.$file_new_name )  )
			// ($file_new_name != '.' &&  $file_new_name != '..' &&  $file_new_name != 'mids' &&  $file_new_name != 'raw' &&  $file_new_name != 'thumbs' )
		{
			echo $file_new_name . "<br />" ;
			
			copy(  $relative_path."/".$file_new_name , $relative_path.'/raw/'.$file_new_name);
			copy(  $relative_path."/".$file_new_name , $relative_path.'/thumbs/'.$file_new_name );
			copy(  $relative_path."/".$file_new_name , $relative_path.'/mids/'.$file_new_name );
			// copy(  $file['tmp_name'] ,$relative_path."/".$file_new_name);
			
			//THUMBS REDIMENSION
			$imageClass->cropImage(200, 200,  $relative_path.'/thumbs/'.$file_new_name , pathinfo( $file_new_name, PATHINFO_EXTENSION), $relative_path.'/thumbs/'.$file_new_name ) ;
			
			//MIDS REDIMENSION
			$imageClass->resize_image( pathinfo( $file_new_name, PATHINFO_EXTENSION) , $relative_path.'/mids/'.$file_new_name , $relative_path.'/mids/'.$file_new_name , 600 , 600 ) ;
			
			//BIG REDIMENSION
			$imageClass->resize_image( pathinfo( $file_new_name, PATHINFO_EXTENSION) , $relative_path."/".$file_new_name , $relative_path."/".$file_new_name , 1500 , 1500 ) ;
			
			
		}
	}
	
		
   
});
//******************************************************************************


?>