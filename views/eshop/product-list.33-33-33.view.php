			<div class="w33 left pr1 mb3 mt2">
				<a class="w100" href="<?= $item['url'] ?>">
					<img class="w100 left clear" src="<?= IMGPATH ?>/mids/<?= $item['illustr_01'] ?>" />
				</a>
				<div class="infos w100 left ">
					<h2 class="bl w70 left txt14 txtblack txtbold uppercase" itemprop="name">
						<a class="" href="<?= URL ?>/eshop-<?= $item['category']['slug'] ?>/<?= $item['id'] ?>-<?= $item['slug'] ?>" itemprop="name">
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
					<p class="bl w70 left  txt16">
						<?= $item['name'] ?>
					</p>
					
				</div>
			</div>