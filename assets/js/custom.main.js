is_mobile = false;

$(document).ready( function(){ 
	
	//*************************************************************************
	//DETECT MOBILES
	is_mobile = false; 
    if( $('.hidem').css('display')=='none' ){is_mobile = true;}
	
	
	if( !is_mobile )
	{
		// IMAGE LOAD SMOOTH
		$('#content img').each( function(index){
			$(this).hide().load( function(){ $(this).animate({top: 0}, 10*index).fadeIn(); });
		
		});
		
		
		//POPIN 
		// $('#popin').hide().drags();
		// window.setTimeout( function(){ $('#popin').fadeIn(1000); } , 1000 ) ;
		// $('#popin_close').click( function()
		// {
			// $('#popin').slideUp();
		// });
		
		
		var feed = new Instafeed({
			get: 'user',
			//tagName: '',
			clientId: 'motmotbijoux' ,
			target : 'instafeed',
			userId: 1535805938,
			accessToken: '141970.467ede5.edbc9c37472d41b790e1db8948793f11',
			sortby: 'most-recent',
			resolution: 'low_resolution',
			links: 'false',
			limit: '16',
		});
		feed.run();
		
		
		
	}
	
	
	
	

});