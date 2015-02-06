<!DOCTYPE html>
<html lang="fr">

	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	<!-- META -->
	<?php include("includes/meta.view.php"); 	?>
	<!-- +++++++++++++++++++++++++++++++++++++++ -->


	<body class="">

		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- HEADER -->
		<?php include("includes/header.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->

		
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		<!-- CONTENT -->
		<div id="" class="line mb3" >
			<!-- container -->
			<div class="container ">
				
				<!-- +++++++++++++++++++++++++ -->	
				<!-- SLIDESHOW -->	
				<div class="w100 left clear   ">
					
					<?php if(sizeof( $slideshow ) > 0 ) : ?>
					<div class="cycle-slideshow w100 left clear "   data-cycle-slides="> .slide" data-cycle-speed="600" data-cycle-manual-speed="600" data-cycle-log="false"   data-cycle-fx="fadeOut" > 
					<!-- +++++++++++++++++++++++++ -->	
						<?php foreach( $slideshow as $item ) : ?>
						<div class="slide relative w100 left clear">
							<a class="w100" <?php if($item['link'] != '' ) : ?>href="<?= $item['link'] ?>" <?php endif; ?>>
								<img class="w100 left clear" src="<?= IMGPATH ?>/<?= $item['illustr'] ?>" />
							</a>
						</div>
						<?php endforeach; ?>
					<!-- +++++++++++++++++++++++++ -->	
					</div>
					<?php endif; ?>
					
				</div>
			</div>
		</div>
		<div id="content" class="line mb3" >
			<!-- container -->
			<div class="container ">
				
				<!-- +++++++++++++++++++++++++ -->	
				<!-- PRODUCT LIST -->	
				<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
				<div class="w100 left clear mb3   ">
				<?php if(sizeof( $products ) > 0 ) : ?>
				<?php foreach( $products as $key => $item ) : ?>
									
					<!-- 50 /50 text  --> 
					<?php if( $key == 0 ) : ?>
						<?php include("eshop/product-list.50-50_text.view.php"); 	?>
					<?php elseif( $key == 1 OR $key == 2 OR $key == 3 OR $key == 7 OR $key == 8 OR $key == 9 OR $key == 12 OR $key == 13 OR $key == 14 ) : ?>
						<?php include("eshop/product-list.33-33-33.view.php"); 	?>
					<?php elseif( $key == 4 ) : ?>	
						<?php include("eshop/product-list.33_text-66.view.php"); 	?>
					<?php elseif( $key == 5 OR $key == 6 OR $key == 10 OR $key == 11  ) : ?>	
						<?php include("eshop/product-list.50-50.view.php"); 	?>
					<?php elseif( $key == 15 OR $key == 16  ) : ?>	
						<?php $key1 = 15; $key2 = 16 ; ?>
						<?php include("eshop/product-list.66-33.view.php"); 	?>	
					<?php endif; ?>
					
				
				<?php endforeach ; ?>
				<?php endif ; ?>
				
				</div>
				<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
				
				
				<!-- +++++++++++++++++++++++++ -->	
				
				
			</div>
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		</div>
		
		
		
		
		
		
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER -->
		<?php include("includes/footer.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
	
	</body>
</html>