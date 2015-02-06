			<div class="w100 left clear mt2">
				<div class="w50 left pr1">
					<a class="w100" href="<?= $item['url'] ?>">
						<img class="w100 left clear" src="<?= IMGPATH ?>/mids/<?= $item['illustr_01'] ?>" />
					</a>
					<div class="infos w100 left ">
						<h2 class="bl w70 left txt14 txtblack txtbold uppercase" itemprop="name">
							<a class="" href="<?= $item['url'] ?>" itemprop="name">
								<?= $item['category']['name'] ?>
							</a>
						</h2>
						<!-- ++++++++ -->
						<!-- PRICE -->
						<span class="w30 price right txtright">
							<?= ( $item['is_promo'] )? $item['promo_price'] : $item['price'] ; ?>€
							<?php if ($item['is_promo'] ) : ?><del class="ACCUEIL-price-old"><?= $item['price'] ?>€</del><?php endif; ?>
						</span>
						<!-- ++++++++ -->
						<p class="bl w70 left  txt16"><?= $item['name'] ?></p>
					</div>
				</div>
				
				<div class="w50 left pl1 ">
					<div class="txtcenter">
						 
					
						<h2 class="txt30 txtblack uppercase " style="margin-top: 50px;" >
							<b>Des bijoux<br /> typographiques</b><br />
							pas comme les autres
						</h2>
						<hr class="w20 mb3 mt1" />
						<p class="">
							<strong>Nous sommes pour la liberté<br />
							d’expression capillaire !<br />
							Et pas que…</strong>
						</p>
						<p class="mt2">
							Exit la morosité, place à la légèreté.<br />
							Les expressions françaises s’incrustent dans votre quotidien.<br />
							Des barrettes et des broches typos en bambou,<br />
							décalées qui ne laisseront personne indifférent.
						</p>
						
					
					</div>
				</div>
			</div>