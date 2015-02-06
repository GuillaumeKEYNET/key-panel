<?php
	$paypal = $payment_config ; 
?>
	<div class="w100 txtcenter txtdarkblue mt3 mb3">
		
		Chargement
		<br />
		
		<img src="<?= URL ?>/assets/images/logo-paypal.jpg" alt="paypal" width="100" /><br />
		<img src="<?= URL ?>/assets/images/paypal_loading.gif" alt="" /><br />
		
		<br />
		Veuillez patienter<br />...
	</div>
	
	<form action="<?= $paypal->serveur ?>" id="formpaypal" method="post">
		
		<input type="hidden" name="upload" value="1">
		<input type="hidden" name="first_name" value="<?= $user_data['client_prenom'] ?>" />
		<input type="hidden" name="last_name" value="<?= $user_data['client_nom'] ?>" />
		<input type="hidden" name="address1" value="<?= $user_data['client_adresse'] ?>" />
		
		<br />
		
		<input type="hidden" name="city" value="<?= $user_data['client_ville'] ?>" />
		<input type="hidden" name="zip" value="<?= $user_data['client_cp'] ?>" />
		<input type="hidden" name="amount" value="<?= $total_commande ?>" />
		<input type="hidden" name="email" value="<?= $user_data['client_email'] ?>">
		<input type="hidden" name="shipping_1" value="<?= $total_carrier ?>" />
		
		<br />
		
		<input type="hidden" name="item_name_1" value="Mon panier" />
		<input type="hidden" name="amount_1" value="<?= $total_cart ?>" />
		<input type="hidden" name="quantity_1" value="1" />
	
		<br />
		
		<input type="hidden" name="charset" value="utf-8">
		<input type="hidden" name="business" value="<?= $paypal->compte ?>" />
		<input type="hidden" name="receiver_email" value="<?= $paypal->compte ?>" />
		<input type="hidden" name="cmd" value="_cart" />
		<input type="hidden" name="currency_code" value="<?= $paypal->devise; ?>" />
		
		<br />
		
		<input type="hidden" name="payer_email" value="<?= $user_data['client_email'] ?>" />
		<input type="hidden" name="return" value="<?= $paypal->url_thanks ?>" />
		<input type="hidden" name="notify_url" value="<?= $paypal->url_confirm; ?>" />
		<input type="hidden" name="cancel_return" value="<?= $paypal->url_error ?>" />
		<input type="hidden" name="invoice" value="<?= $reference ?>" />
         
		<br />

		<?php /* <input type="submit"  value="PAYER" /> */ ?>

		
		
	</form>
	
	<script>
		$(document).ready( function(){
				setTimeout(function(){  document.getElementById('formpaypal').submit() }, 700);

		});
	
	</script>