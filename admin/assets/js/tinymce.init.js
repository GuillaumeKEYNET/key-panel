tinymce.PluginManager.add("fullscreen",function(a){function b(){var a,b,c=window,d=document,e=d.body;return e.offsetWidth&&(a=e.offsetWidth,b=e.offsetHeight),c.innerWidth&&c.innerHeight&&(a=c.innerWidth,b=c.innerHeight),{w:a,h:b}}function c(){function c(){j.setStyle(m,"height",b().h-(l.clientHeight-m.clientHeight))}var k,l,m,n,o=document.body,p=document.documentElement;i=!i,l=a.getContainer(),k=l.style,m=a.getContentAreaContainer().firstChild,n=m.style,i?(d=n.width,e=n.height,n.width=n.height="100%",g=k.width,h=k.height,k.width=k.height="",j.addClass(o,"mce-fullscreen"),j.addClass(p,"mce-fullscreen"),j.addClass(l,"mce-fullscreen"),j.bind(window,"resize",c),c(),f=c):(n.width=d,n.height=e,g&&(k.width=g),h&&(k.height=h),j.removeClass(o,"mce-fullscreen"),j.removeClass(p,"mce-fullscreen"),j.removeClass(l,"mce-fullscreen"),j.unbind(window,"resize",f)),a.fire("FullscreenStateChanged",{state:i})}var d,e,f,g,h,i=!1,j=tinymce.DOM;return a.settings.inline?void 0:(a.on("init",function(){a.addShortcut("Meta+Alt+F","",c)}),a.on("remove",function(){f&&j.unbind(window,"resize",f)}),a.addCommand("mceFullScreen",c),a.addMenuItem("fullscreen",{text:"Fullscreen",shortcut:"Meta+Alt+F",selectable:!0,onClick:c,onPostRender:function(){var b=this;a.on("FullscreenStateChanged",function(a){b.active(a.state)})},context:"view"}),a.addButton("fullscreen",{tooltip:"Fullscreen",shortcut:"Meta+Alt+F",onClick:c,onPostRender:function(){var b=this;a.on("FullscreenStateChanged",function(a){b.active(a.state)})}}),{isFullscreen:function(){return i}})});


$(function() {
				$('textarea.tinymce').tinymce({
					plugins: 'textcolor,media,code,image,link',
					theme : "modern",
					content_css : ["<?= URL ?>/assets/js/tinymce/content.css?" + new Date().getTime() , "http://fonts.googleapis.com/css?family=Pacifico" ] ,
					height: "300",
					relative_urls: false,
					menubar : false , 
					statusbar: false,
					
					toolbar: [ "alignleft aligncenter alignright | bold italic underline uppercase | bullist | forecolor styleselect fontsizeselect | link unlink media image | code removeformat fullscreen " ] ,
						
					
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