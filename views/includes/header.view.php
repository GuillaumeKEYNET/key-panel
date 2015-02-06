

	<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
	<div id="header" class="line  pt3 pb3" >
		
		<!-- +++++++++++ -->
		<!-- LOGO -->
		<h1 id="logo" class="txtcenter ">
			<a href="/"><img src="<?= ASSETS ?>/images/motmotbijoux-logo.png" alt="MotMot Bijoux" /></a>
		</h1>
		<!-- +++++++++++ -->
		
		<!-- +++++++++++ -->
		<!-- TOP LINKS -->
		<div id="toplinks" class="right txtright">
			<a href="/eshop/cart" >
				My bag (<?= count($cart) ?>)
			</a>
		</div>
		<!-- +++++++++++ -->
		
		<!-- +++++++++++ -->
		<!-- TOP SOCIALS -->
		<div id="topsocials" class="left txtleft hidem">
			<a href="https://www.facebook.com/pages/Motmotbijoux/447173055420883?ref=hl" target="_blank" class=" inbl pa1" ><img src="<?= ASSETS ?>/images/facebook.png" alt="facebook" /></a>
			<a href="http://www.pinterest.com/motmotbijoux" target="_blank" class=" inbl pa1" ><img src="<?= ASSETS ?>/images/pinterest.png" alt="pinterest" /></a>
			<a href="http://www.instagram.com/motmotbijoux" target="_blank" class=" inbl pa1" ><img src="<?= ASSETS ?>/images/instagram.png" alt="instagram" /></a>
		</div>
		<!-- +++++++++++ -->
	</div>
	
	<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
	
	<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
	<!-- NAV -->
	<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
	<div id="nav" class="line  pt3 pb3 txtcenter" >
		<a id="homelink" href="/" class=" <?= ($meta['url'] == '/' )? 'active': '' ; ?>" >Voir toute la collection</a>	
		<a id="a-7" href="<?= URL ?>/eshop-broche-a-cheveux" class="<?= ($meta['url'] == '/eshop-broche-a-cheveux' )? 'active': '' ; ?>" >Broche à cheveux</a>
		<a id="a-8" href="<?= URL ?>/eshop-broche-a-fringue" class="<?= ($meta['url'] == '/eshop-broche-a-fringue' )? 'active': '' ; ?>" >Broche à fringue</a>
		
		<a id="a-13" href="<?= URL ?>/commandes-speciales" class="<?= ($meta['url'] == '/commandes-speciales' )? 'active': '' ; ?>" >commandes spéciales</a>
			
		<a id="a-14" href="<?= URL ?>/presse" class="<?= ($meta['url'] == '/presse' )? 'active': '' ; ?>" >presse</a>
			
		<a id="a-11" href="<?= URL ?>/a-propos" class="<?= ($meta['url'] == '/a-propos' )? 'active': '' ; ?>" >À PROPOS</a>
	</div>
	<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
	