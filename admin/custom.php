<?php

//******************************************************************************
// DASHBOARD
$app->get('/dashboard', function () use ($app) {
   
	/*
	require_once('GoogleAnalyticsAPI.class.php');
	// $ga = new GoogleAnalyticsAPI('mon_adresse@gmail.com', 'mon_password', 'mon_id', date('Y-m-d', time()));
	// $ga = new GoogleAnalyticsAPI('guillaume.clenet@gmail.com', 'tiatia12', '98253319', date('Y-m-d', time()));
	// $navigateurs = $ga->getDimensionByMetric('pageviews', 'browser');
	
	$ga_begda = date('Y-m-d', strtotime( '-1 month', time()  ) );
	$ga_endda = date('Y-m-d', time() );
	$ga = new GoogleAnalyticsAPI('guillaume.clenet@gmail.com', 'tiatia12', '98253319',  $ga_begda, $ga_endda);
	$ga->setMaxResults( 40 );
	$ga->setSortByDimensions( true );
	$stats['visits'] = $ga->getMetric('sessions');
	$stats['sessions'] = $ga->getDimensionByMetric('sessions' , 'date' );
	
	foreach( $stats['sessions']['labels'] as $key => $item )
	{
		// echo substr($item , 0 , 8 ).' ::: '.strtotime( substr($item , 0 , 8 ) ) ."<br />";

		$stats['sessions']['labels'][$key] = date('d/m/Y' , strtotime( substr($item , 0 , 8 ) ) ) ;
	}
	// exit;
	// $output ="";
	// $output .=  '<pre>';
	// ob_start();
	// print_r($stats);
	// $output .= ob_get_clean();
	// $output .=  '</pre>';
	
	*/
	
	//RENDER
	$app->render('dashboard.view.php', array(
		// 'stats' => $stats,
		// 'races' => $races,
		 
	) );
		
   
});
//******************************************************************************
// TABLEAU
$app->get('/tableau-courses', function () use ($app) {
   
	//GET ALL MEMBERS
	$members = $app->database->select('member' , '*' , [ 'ORDER' => 'orden' ] );
	
	//GET ALL RACES
	$races = $app->database->select('race' , '*' , [ 'AND' => [ 'visible' => 1 ] , 'ORDER' => [ 'date', 'orden'] ] );
	
	//GET ALL MEMBER_RACE
	foreach( $races as $key => $item )
	{
		$inscrits = $app->database->select( 'race_member'  , '*' , [ 'AND' => [ 'race_id' => $item['id'] ] ]  );
		foreach( $inscrits as $inscrit )
		{
			$races[$key]['inscrits'][$inscrit['member_id']] = $inscrit;
		}
	}
	
	
	
	//RENDER
	$app->render('tableau-courses.view.php', array(
		'members' => $members,
		'races' => $races,
		 
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