<!doctype html>
<!--[if lte IE 7]> <html class="no-js ie67 ie678" lang="fr"> <![endif]-->
<!--[if IE 8]> <html class="no-js ie8 ie678" lang="fr"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="fr"> <![endif]-->
<!--[if gt IE 9]> <!--><html class="no-js" lang="fr"> <!--<![endif]-->


	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	<!-- HTML_HEADER -->
	<?php include("global/meta.view.php"); 	?>
	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	
<body>

	<div class="container ">
				
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- HEADER -->
		<?php include("global/header.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
		<!-- ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		<div id="content"> 
			
			
			<!-- ............................................................................................................ -->
			<!-- VOTRE COMMANDE -->
			<div class="left w100 clear mb2">
				<h2 class="w100 left bgdarkgrey txtwhite txtdin txt26 pl2 ">
					Votre commande
				</h2>
			</div>
			
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			<!-- TUNNEL ARIANE -->
			<?php include("global/tunnel-ariane.view.php"); 	?>
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			
			<!-- ............................................................................................................ -->
			<div class="left w100 clear txt11 ">
				<div class="txtdarkblue txtcenter">Référence Commande <?= $reference ?></div>
				
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					<!-- HEADER -->
					<?php include("payment/paypal.view.php"); 	?>
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
				
				
			</div>
			<!-- .................................... -->
			
			
			<!-- .................................... -->
			<!-- SPACE -->
			<div class="left clear mt2"></div>
			<!-- .................................... -->
			
			 
		
		</div>
		<!-- ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		
		<!-- .................................... -->
		<!-- SPACE -->
		<br class="clear" />
		<div class="w100 left clear mb2"></div>
		<!-- .................................... -->
		
		
		
		
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER BOXES-->
		<?php //include("global/footer_boxes.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
		
		
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER -->
		<?php //include("global/footer.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
		
<script type="text/javascript">

var _gaq = _gaq || [];
_gaq.push(['_setAccount', 'UA-9328862-1']);
_gaq.push(['_trackPageview']);

(function() {
var ga = document.createElement('script'); ga.type = 'text/javascript'; ga.async = true;
ga.src = ('https:' == document.location.protocol ? 'https://ssl' : 'http://www') + '.google-analytics.com/ga.js';
var s = document.getElementsByTagName('script')[0]; s.parentNode.insertBefore(ga, s);
})();

</script>
		
		
		
				
				
	</div>



	
</body>
</html>