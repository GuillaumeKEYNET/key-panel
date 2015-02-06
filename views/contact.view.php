<!doctype html>
<!--[if lte IE 7]> <html class="no-js ie67 ie678" lang="fr"> <![endif]-->
<!--[if IE 8]> <html class="no-js ie8 ie678" lang="fr"> <![endif]-->
<!--[if IE 9]> <html class="no-js ie9" lang="fr"> <![endif]-->
<!--[if gt IE 9]> <!--><html class="no-js" lang="fr"> <!--<![endif]-->


	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	<!-- HTML_HEADER -->
	<?php include("includes/meta.view.php"); 	?>
	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	
<body>

	<div class="container ">
				
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- HEADER -->
		<?php include("includes/header.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
		<!-- ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		<div id="content">
			
			<!-- .................................... -->
			<!-- TITLE -->
			<div class="left w100 clear mb2">
				<h2 class="w100 left bgblue txtwhite txtdin txt26 pl2 ">
					Contact
				</h2>
			</div>
			<!-- .................................... -->

			<div class="w33 left clear" >
				<?= $page['text_'.$lang] ?>
			</div>
			
			
			<!-- success -->
			<?php if( isset( $flash['success'] ) && $flash['success'] ) : ?>
				<div class="w66 pl2 left">
					<div class=" notification w100 clear txt12 mb2" style="">Message envoyé</div>
				</div>
				<script>jQuery(document).ready(function() {jQuery( ".notification" ).delay(500).hide().slideDown(800);});	</script>
			<?php else :  ?>
			
			<form method="POST" action="<?= URL ?>/contact/send" >
			<div class="w66 pl2 left">
				
				<!-- info -->
				<?php if( isset( $flash['error'] )) : ?>
					<div class=" notification w100 clear txt12 mb2" style=""><b>Erreur</b>, merci de bien vouloir verifier vos champs</div>
					<script>jQuery(document).ready(function() {jQuery( ".notification" ).delay(500).hide().slideDown(800);});	</script>
				<?php endif; ?>
				
				<p class="left clear txt11 txtblue">
					
					
				
				</p>
				
				<div class="w100 left clear mt1">
					<input type="text" name="nom" placeholder="Votre nom" class="w50 inputblue inputshadow txt11 <?= ( isset($flash['form_data']) && @$flash['form_data']['nom']=='') ? 'error' : ''  ?>"  value="<?= @$flash['form_data']['nom'] ?>"  /><br />
					<input type="text" name="email" placeholder="Votre E-mail" class="w50 inputblue inputshadow mtv txt11 <?= ( isset($flash['form_data']) && @$flash['form_data']['email']=='') ? 'error' : ''  ?>"  value="<?= @$flash['form_data']['email'] ?>" /><br />
					<textarea class="inputblue w100 h200p <?= ( isset($flash['form_data']) && @$flash['form_data']['message']=='') ? 'error' : ''  ?>" name="message"  ><?= @$flash['form_data']['message'] ?></textarea>
					<br  class="clear" />
					<input type="submit" class="right bgblue txtwhite border0 button pl1 pr1 ptv pbv mtv" style="padding: 10px 40px;" value="Envoyer" />
				
				
				
				</div>
			
			
			
			</div>
			</form>
			<?php endif; ?>
			
			
		</div>
		<!-- ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		
		
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER -->
		<?php include("includes/footer.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
		
		
		
		
				
				
	</div>



	
</body>
</html>


