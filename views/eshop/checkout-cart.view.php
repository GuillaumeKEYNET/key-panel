			
				<hr class="w30">			
				
				<h1 class=" clear txt30 txtcenter txtblack txtbold uppercase mt2 mb2">
					Mon panier : 
					<span>
						<?= $cart_total ?> €<span class="it">&nbsp;TTC</span>						
					</span>
				</h1>
				
				<hr class="w30">			
				
				<div class="w100 left clear txt12 txtarial txtcenter mb3">
					<p class="checkout-contact">
						Une question ? Un conseil ?<br>
						<strong>Contactez-nous <a href="<?= URL ?>/contact">Par email</a></strong>
					</p>
				</div>
					
				<?php if( count ($cart) >0  ) : ?>		
					
					<!-- .................................... -->
					<!-- NUMBER OF ITEMs IN CART  -->
					<div class=" clear w100 txtcenter txt18  mb2">
						<?php if( count($cart)==1 ) : ?>
							1 article a été ajouté à votre panier
						<?php else : ?>
							<?= count($cart) ?> articles ont été ajoutés à votre panier
						<?php endif; ?>
					</div>
					<!-- .................................... -->
				
				
				
				<table id="cart" class="w100 center clear">
				
					<thead>
						<tr class="txtleft bgblack txtwhite txt14 pa2">
							<th colspan="2">Produit</th>
							<th>Disponibilité</th>
							<th>Prix unit.</th>
							<th>Quantité</th>
							<th>Sous Total</th>	
							<th>&nbsp;</th>	
						</tr>
					</thead>
				
					<tbody>
						<!-- .................................... -->
						<?php /*FOREACH*/ foreach( $cart as $key => $item ) : ?>	
						<tr>
							<td><img class="w50p left ma1" src="<?= IMGPATH ?>/thumbs/<?= $item['product']['illustr_01'] ?>" alt="<?= $item['product']['name'] ?>" /></td>
							<td><?= $item['product']['name'] ?></td>
							<td><?= ($item['product']['stock']>0)?'en stock':'indisponible'; ?></td>
							<td>
								<!-- PRICE -->
								<span class=" price  txtright">
									<b><?= ( $item['product']['is_promo'] )? $item['product']['promo_price'] : $item['product']['price'] ; ?>€</b>
									<br />
									<?php if ($item['product']['is_promo'] ) : ?><del class="ACCUEIL-price-old"><?= $item['product']['price'] ?>€</del><?php endif; ?>
								</span>
								<!-- ++++++++ -->
							</td>
							<td><?= $item['product']['quantity'] ?></td>
							<td><b><?= $item['product']['total'] ?> €</b></td>	
							<td><a href="<?= URL ?>/eshop/removefromcart?key=<?= $key ?>" class="txtgrey mr2"  ><span class="icon-cross"></span></a></td>	
						</tr>
						<?php /*FOREACHEND*/ endforeach; ?>
						<!-- .................................... -->
						
						
						<tr>
							<td colspan="4">&nbsp;</td>
							<td><b>Frais de port</b></td>
							<td colspan="2">offert</td>
						
						</tr>
					</tbody>
					
					<tfoot>
						<tr class="txtleft bgblack txtwhite txt16 pa2">
							<th colspan="3">&nbsp;</th>
							<th colspan="2">TOTAL DE VOTRE PANIER </th>
							<th colspan="2"><?= $cart_total ?> €</th>	
						</tr>
					</tfoot>
					
				</table>
				
				
				<a href="<?= URL ?>/checkout/informations" class="right border0 txtwhite txt20 bgblack txtcenter pr3 pl3 ptv pbv">
					Commander
				</a>	
				
				<?php else:  ?>
					<div class="w100 left clear mb2 txtblack txt12" >
						Aucun article dans votre panier.
					</div>
				<?php /*IF END*/ endif; ?>
					
			</div>	
			<!-- .................................... -->