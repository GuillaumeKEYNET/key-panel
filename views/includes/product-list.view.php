		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		<div class="w100 left clear mb3   ">
		<?php if(sizeof( $products ) > 0 ) : ?>
		<?php foreach( $products as $key => $item ) : ?>
							
			<?php if( $key == 0 ) : ?>
			<!-- +++++++++++++++++++++++++ -->
			<!-- 50 /50 text  --> 
			
			<?php endif; ?>
			
			<?php if( $key == 1 OR $key == 2 OR $key == 3 OR $key == 7 OR $key == 8 OR $key == 9 OR $key == 12 OR $key == 13 OR $key == 14 ) : ?>
			<!-- SI ACCUEIL.NUM_LIGNE egal 1 ou ACCUEIL.NUM_LIGNE egal 2 ou ACCUEIL.NUM_LIGNE egal 3 ou ACCUEIL.NUM_LIGNE egal 7 ou ACCUEIL.NUM_LIGNE egal 8 ou ACCUEIL.NUM_LIGNE egal 9 ou ACCUEIL.NUM_LIGNE egal 12 ou ACCUEIL.NUM_LIGNE egal 13 ou ACCUEIL.NUM_LIGNE egal 14   -->	
			<!-- +++++++++++++++++++++++++ -->
			<!-- 33 / 33 / 33  -->
			<div class="w33 left pr1 mb3 mt2">
				<a class="w100" href="{ACCUEIL.URL}">
					<img class="w100 left clear" src="<?= IMGPATH ?>/<?= $item['illustr_01'] ?>" />
				</a>
				<div class="infos w100 left ">
					<h2 class="bl w70 left txt14 txtblack txtbold uppercase" itemprop="name">
						<a class="" href="{ACCUEIL.URL}" itemprop="name">
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
			<?php endif; ?>
			
			<?php if( $key == 4 ) : ?>			
			<!-- SI ACCUEIL.NUM_LIGNE egal 4 -->	
			<!-- +++++++++++++++++++++++++ -->
			<!-- 33 text / 66  -->
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
						<a class="w100 mb1 doublebloc" href="{ACCUEIL.URL}"   >
							<img class="w100 left clear" src="<?= IMGPATH ?>/<?= $item['illustr_01'] ?>"   />
						</a>
						<div class="infos w100 left ">
							<h2 class="bl w70 left txt14 txtblack txtbold uppercase" itemprop="name">
								<a class="" href="{ACCUEIL.URL}" itemprop="name">
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
			<?php endif; ?>
			
			<?php if( $key == 5 OR $key == 6 OR $key == 10 OR $key == 11  ) : ?>	
			<!-- SI ACCUEIL.NUM_LIGNE egal 5 ou ACCUEIL.NUM_LIGNE egal 6 ou ACCUEIL.NUM_LIGNE egal 10 ou ACCUEIL.NUM_LIGNE egal 11 -->	
			<!-- +++++++++++++++++++++++++ -->
			<!-- 50 /50  -->
			<div class="w50 left pr1 mt2">
				<a class="w100" href="{ACCUEIL.URL}">
					<img class="w100 left clear" src="<?= IMGPATH ?>/<?= $item['illustr_01'] ?>" />
				</a>
				<div class="infos w100 left ">
					<h2 class="bl w70 left txt14 txtblack txtbold uppercase" itemprop="name">
						<a class="" href="{ACCUEIL.URL}" itemprop="name">
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
			<?php endif; ?>
			
			<?php if( $key == 15 OR $key == 16  ) : ?>	
			<!-- SI ACCUEIL.NUM_LIGNE egal 15 ou ACCUEIL.NUM_LIGNE egal 16 -->	
			<!-- +++++++++++++++++++++++++ -->
			<!-- 66 /33   -->
			<!-- SI ACCUEIL.NUM_LIGNE egal 15 -->	
			<div class="w100 left clear ">
				<div class="w66 left pr1">
					<div class="slide relative w100 left clear">
						<a class="w100 mb1 doublebloc" href="{ACCUEIL.URL}"   >
							<img class="w100 left clear" src="<?= IMGPATH ?>/<?= $item['illustr_01'] ?>"   />
						</a>
						<div class="infos w100 left ">
							<h2 class="bl w70 left txt14 txtblack txtbold uppercase" itemprop="name">
								<a class="" href="{ACCUEIL.URL}" itemprop="name">
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
				<!-- SINON -->
				<div class="w33 left pr1">
					<div class="slide relative w100 left ">
						<a class="w100" href="{ACCUEIL.URL}">
							<img class="w100 left clear" src="<?= IMGPATH ?>/<?= $item['illustr_01'] ?>" />
						</a>
						<div class="infos w100 left ">
							<h2 class="bl w70 left txt16 txtblack txtbold uppercase" itemprop="name">
								<a class="" href="{ACCUEIL.URL}" itemprop="name">
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
			<?php endif; ?>
			
		
		<?php endforeach ; ?>
		<?php endif ; ?>
		
		</div>
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->