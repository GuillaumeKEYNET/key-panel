
		<?php $item = $product ; ?>
		
		<form id="prod-form"  action="<?= URL ?>/eshop/addtocart" method="post" enctype="multipart/form-data"  itemscope itemtype="http://schema.org/Product">
			
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
			<!-- 50 /50  -->
			<div class="w100 left clear ">
				
				<!-- .................................................... -->
				<div class="w50 left pr1">
					<div id="product_img" class=" w100 left clear">
						<img class=" w100 " src="<?= IMGPATH ?>/mids/<?= $item['illustr_01'] ?>" />
					</div>
					<div class="product_thumbs w100 left clear mt2">
						<a href="<?= IMGPATH ?>/mids/<?= $item['illustr_01'] ?>" title="<?= $item['name'] ?>"><img src="<?= IMGPATH ?>/thumbs/<?= $item['illustr_01'] ?>"  /></a>
						<?php if( $item['illustr_02'] ) : ?><a href="<?= IMGPATH ?>/mids/<?= $item['illustr_02'] ?>" title="<?= $item['name'] ?>"><img src="<?= IMGPATH ?>/thumbs/<?= $item['illustr_02'] ?>"  /></a><?php endif; ?>
						<?php if( $item['illustr_03'] ) : ?><a href="<?= IMGPATH ?>/mids/<?= $item['illustr_03'] ?>" title="<?= $item['name'] ?>"><img src="<?= IMGPATH ?>/thumbs/<?= $item['illustr_03'] ?>"  /></a><?php endif; ?>
					</div>
				</div>
				<!-- .................................................... -->
				
				<!-- .................................................... -->
				<div class="w50 left pl1 txtleft ">
					 
					<h1 class=" clear txt30 txtblack txtbold uppercase " itemprop="name">
						<?= $item['name'] ?>
					</h1>
					
					<h2 class="txt30 txtnobold  uppercase" itemprop="description">
						<?= $item['desc'] ?>
					</h2>
					
					<hr class="w20 left clear mt2" />
					
					<div class="bl w100 txt26 left clear mt2" >
						<?= $item['desc'] ?>
					</div>
					
					<div class="bl w100  txt14 left clear mt2">
						<ul id="features-ul">
							<li class="features-li">
								<?= str_replace(array("\r","\n\n","\n"),array('',"\n","</li>\n<li>"),trim($item['details'],"\n\r")) ?>
							</li>
						</ul>
					</div>
					
					
					<!-- SI pas PROD.INDISPONIBLE et pas $NOCOMMERCE -->
						<div class="bl w100  txt14 left clear mt2">
							
							<p>STOCK : <?= $item['stock'] ?></p>
							
							<p id="price" class="w100 left clear txt20 mb1" itemprop="offers" itemscope itemtype="http://schema.org/Offer">
								<strong class="price-cur-container"><?= ( $item['is_promo'] )? $item['promo_price'] : $item['price'] ; ?>€</strong>
								<?php if ($item['is_promo'] ) : ?><del class="ACCUEIL-price-old"><?= $item['price'] ?>€</del><?php endif; ?>
							</p>
							
							<select class="input w45 left" id="quantity" name="quantity" >
								<option value="1">Quantité</option>
								<?php for( $i=1; $i<= $item['stock'] && $i<=10 ; $i++ ) : ?>
								<option value="<?= $i ?>" ><?= $i ?></option>
								<?php endfor; ?>
							</select>
							
							
							<input type="submit" class="button w50 right" value="AJOUTER AU PANIER" />
							<input type="hidden" name="product_id" value="<?= $item['id'] ?>" />
							
							<!-- SI W_C_STOCK et pas PROD.VARIATION2 -->
							<meta itemprop="availability" href="http://schema.org/<!-- SI PROD.STOCK -->InStock<!-- SINON -->OutOfStock<!-- FINSI -->" content="<!-- SI PROD.STOCK_PHRASE -->{PROD.STOCK_PHRASE}<!-- SINONSI PROD.STOCK -->{L_EN_STOCK}<!-- SINON -->{L_STOCK_EPUISE}<!-- FINSI -->" />
							<!-- FINSI -->
							
						</div>
					<!-- SINON -->
						<div class="bl w100  txt14 left clear mt2">
							<!--<p>Produit indisponible, <i>pour le moment</i>.</p>-->
						</div>
					<!-- FINSI -->
						
					 
				</div>
			</div>
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
			
			
		
		</form>
		
		<!-- ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		<!-- SI PROD.LIST_CROSS -->
		<div class="w100 left clear mt3 pt2 bordert2 borderblack txtcenter">
			<h3 class="txtcenter txtbold txt26 ">
				ça pourrait vous plaire
			</h3>
			<!-- DEBUT LIST_CROSS(0,3) -->
				<div class="w30 inbl pr1 ma1 mt2">
					<a href="{LIST_CROSS.URL}" title="{LIST_CROSS.NOM}" class="w100" >
						<img src="{LIST_CROSS.IMG}" alt="{LIST_CROSS.NOM}" class="w100   clear"  />	
					</a>
				</div>
			<!-- FIN LIST_CROSS -->
		
		</div>
		<!-- FINSI -->
		<!-- ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
	

	<!-- FIN PROD -->






	<script>
		
		$(document).ready( function(){
			
			
			$('.product_thumbs a').click( function(e){
				e.preventDefault();
				
				src = $(this).attr('href');
				$("#product_img > img").attr('src', src ).hide().fadeIn(600);
				
				return false;
			
			})
		
		});
	
	
	</script>

