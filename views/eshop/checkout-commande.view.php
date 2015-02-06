
			
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			<!-- CHECKOUT ARIANE -->
			<?php include("checkout-ariane.view.php"); 	?>
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			
			<!-- ............................................................................................................ -->
			<div class="left w100 clear  ">
				<?php if( count ($cart) >0  ) : ?>	
				<form method="POST" action="<?= URL ?>/checkout/payment" >
				
				<style>
					.w48{ width: 48%; }
				</style>
				<!-- .................................... -->	
				<!-- INFORMATIONS RECAP -->	
				<div class="w48 w100m left mb2" >
					
					<div class="w100 pa1 border1 bordergrey">
						<h2 class="w100 left clear mt2 mb2 txt18 txtcenter bgblack txtwhite pa1">
							Informations
						</h2>
						
						
						<b><?= @$infos['client_civilite'] ?> <?= @$infos['client_prenom'] ?> <?= @$infos['client_nom'] ?></b><br />
						<?= @$infos['client_email'] ?><br />
						<?= @$infos['client_tel'] ?><br />
						<?= @$infos['client_adresse'] ?><br />
						<?= @$infos['client_cp'] ?> <?= @$infos['client_ville'] ?> <?= @$infos['client_pays'] ?><br />
						<?= @$infos['client_infos'] ?><br />
						
						<?php if ( @$infos['livraison_different'] == 'on' ) : ?>
						<br /><i class="txtcenter">Livraison</i><br />
						<b><?= @$infos['livraison_civilite'] ?> <?= @$infos['livraison_prenom'] ?> <?= @$infos['livraison_nom'] ?></b><br />
						<?= @$infos['livraison_email'] ?><br />
						<?= @$infos['livraison_tel'] ?><br />
						<?= @$infos['livraison_adresse'] ?><br />
						<?= @$infos['livraison_cp'] ?> <?= @$infos['livraison_ville'] ?> <?= @$infos['livraison_pays'] ?><br />
						<?= @$infos['livraison_infos'] ?><br />
						
						
						<?php endif; ?>
				
					</div>
				</div>
				
				<!-- .................................... -->	
				<!-- CART RECAP -->	
				<div class="right w50  mb2 ">
					<div class="left w100 pa1 border1 bordergrey">
						<h2 class="w100 left clear mt2  txt18 txtcenter bgblack txtwhite pa1">
							Votre Panier
						</h2>
						
						<!-- .................................... -->
						<?php /*FOREACH*/ foreach( $cart as $key => $item ) : ?>	
							<div class="w100 left mtv clear" style="border-bottom: 1px dotted grey;" >
								<img class="w50p left mbv mr1 " src="<?= IMGPATH ?>/thumbs/<?= $item['product']['illustr_01'] ?>" alt="<?= $item['product']['name'] ?>"  />
								<div class="left mt1"><?= $item['product']['quantity'] ?> x <?= $item['product']['name'] ?></div>
								<div class="txtright right txtbold pav"><?= $item['product']['total'] ?> €</div>	
							</div>
						<?php /*FOREACHEND*/ endforeach; ?>
							<div class="w100 left mtv clear" style="border-bottom: 1px dotted grey;" >
								<div class="left mt1">Frais de port</div>
								<div class="txtright right txtbold pav">offert</div>	
							</div>
						
						<div class="w100 mtv left clear bgblack pav txtwhite txtbold" >
							TOTAL : <div class="txtright right txtbold"><?= $cart_total ?> €</div>
						</div>	
					</div>	
				</div>	
				
				<!-- .................................... -->
				<!-- CARRIER  -->
				
				<div class="w48 w100m   mb2 left clear hide ">
					<div class="left w100 pa1 border1 bordergrey">
						<h2 class="w100 left clear mt2  txt18 txtcenter bgblack txtwhite pa1">
							Moyen de livraison
						</h2>
						<!-- .................................... -->
						<?php /*FOREACH*/ if( @$carriers ) foreach( $carriers as $key => $item ) : ?>	
						<div class="w100 left mav clear	"  >
							<label><input type="radio" name="carrier_id" value="<?= $item['id'] ?>" class=" ml1 mr1"  <?= ($key==0)? 'checked="checked"' : '' ; ?> /><?= $item['name'] ?></label>
						</div>						
						<?php /*FOREACHEND*/ endforeach; ?>
					</div>
				</div>
				
				<!-- .................................... -->
				
				<!-- .................................... -->
				<!-- PAYMENT METHOD  -->
				<div class="w50  clear mb2 right   ">
					<div class="left w100 pa1 border1 bordergrey">
						<h2 class="w100 left clear mt2  txt18 txtcenter bgblack txtwhite pa1">
							Moyen de paiement
						</h2>
						<!-- .................................... -->
						<?php /*FOREACH*/ if( @$payments ) foreach( $payments as $key => $item ) : ?>	
						<div class="w100 left mav clear	"  >
							<label>
								<input type="radio" name="payment_id" value="<?= $item['id'] ?>" class=" ml1 mr1" <?= ($key==0)? 'checked="checked"' : '' ; ?> />
								<img src="<?= IMGPATH ?>/<?= $item['illustr'] ?>" alt="<?= $item['name'] ?>" title="<?= $item['name'] ?>" />
							</label>
						</div>						
						<?php /*FOREACHEND*/ endforeach; ?>
						
					</div>
				</div>
				<!-- .................................... -->		
				
					
				<!-- .................................... -->
				<!-- COMMAND BUTTON  -->
				<div class="w100  mt2 mb2 left clear  ">
					<a href="<?= URL ?>/checkout/informations" class="border0 txtwhite txt12 bgdarkgrey txtcenter pr3 pl3 ptv pbv">Retour</a>
					<div class="  right   ">
						<input type="submit" class="border0 txtwhite txt20 bgblack txtcenter pr3 pl3 ptv pbv" value="Valider et Payer" />
					</div>
				</div>
				<!-- .................................... -->
				
				
				</form>
				<?php else:  ?>
					<div class="w100 left clear mb2 txtblack txt12" >
						Aucun article dans votre panier.
					</div>
				<?php /*IF END*/ endif; ?>
					
			</div>	
			<!-- .................................... -->
			
			
			<!-- .................................... -->
			<!-- SPACE -->
			<div class="left clear mt2"></div>
			<!-- .................................... -->
			
			 
		
		