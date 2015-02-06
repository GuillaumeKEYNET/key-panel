				<div class="w100 left clear mt2">
					<div class="w33 left pr1">
						<div class="w100 pa1 txtcenter  ">
						
							<h2 class="txt24 txtblack"  >
								<strong>IMPOSSIBLE</strong> N’EST <br />PAS FRANÇAIS
							</h2>
							<hr class="w20 mb3 mt1" />
							<p class="mt2">
								Nous on y croit ! C’est pour ça que toutes nos<br />
								créations sont fabriquées en France.
							</p>
							<p class="mt2">
								Nous portons une grande attention à nos<br />
								produits et à ceux qui nous aident à les<br />
								fabriquer. Le respect de l’environnement est<br />
								une évidence. Nous utilisons du bambou<br />
								certifié FSC®.
							</p>
							<p class="mt2 txtbold">
								Parce que nous pensons<br />
								aussi aux Pandas.
							</p>
						
						</div>
					</div>
					
					<div class="w66 left pr1">
						<div class="slide relative w100 left clear">
							<a class="w100 mb1 doublebloc" href="<?= $item['url'] ?>"   >
								<img class="w100 left clear" src="<?= IMGPATH ?>/mids/<?= $item['illustr_01'] ?>"   />
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
								<p class="bl w70 left  txt16">
									<?= $item['name'] ?>
								</p>
								
							</div>
					
						</div>
					</div>
				</div>