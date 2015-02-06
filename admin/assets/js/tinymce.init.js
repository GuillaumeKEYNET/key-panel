$(function() {
				$('textarea.tinymce').tinymce({
					plugins: 'textcolor,media,code,image,link',
					theme : "modern",
					content_css : ["<?= URL ?>/assets/js/tinymce/content.css?" + new Date().getTime() , "http://fonts.googleapis.com/css?family=Pacifico" ] ,
					height: "300",
					relative_urls: false,
					menubar : false , 
					statusbar: false,
						toolbar: [ "styleselect forecolor backcolor bullist | bold italic | link unlink media image | alignleft aligncenter alignright | code " ]
						
					
						// font_formats: "Andale Mono=andale mono,times;"+// "Arial=arial,helvetica,sans-serif;"+
      
						/*
						fontsize_formats: "8px 10px 11px 12px 14px 18px 22px 26px 30px",

						style_formats: [
							{title: 'Futura', inline: 'span' , classes: 'txtfutura'},
							{title: 'Pacifico', inline: 'span' , classes: 'txtpacifico'},
							{title: ''},
							{title: 'SEO H1', inline: 'h1'  },
							{title: 'SEO H2', inline: 'h2'  },
							{title: 'SEO H3', inline: 'h3'  }
						],
						textcolor_map: [
							  "000", "black",
							  "777", "grey",
							  "A4A47F", "grey2",
							  "AFD1AB", "green",
							  "E1EBA9", "green2",
							  "BD5532", "red",
							  "E95E27", "orange",
							  "4B7D82", "blue",
							  "55B5B3", "blue2",
							  "2AB088", "turquoise",
							  "CBD300", "yellow",
						],

						
						toolbar: [ "alignleft aligncenter alignright | bold italic underline uppercase | bullist | forecolor styleselect fontsizeselect | link unlink media image | code removeformat  " ] ,
						*/
						file_browser_callback: custom_file_browse ,
				});
			});