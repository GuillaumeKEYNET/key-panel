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
		<div id="content" class="line mb3" >
			<!-- container -->
			<div class="container ">
				
				<h1 class="h1 txtbold txt36 txtcenter w100 left uppercase hide"><strong><?= $category['name'] ?></strong></h1>
				
				<!-- +++++++++++++++++++++++++ -->	
				<!-- PRODUCT LIST -->	
				<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
				<div class="w100 left clear mb3   ">
				<?php if(sizeof( $products ) > 0 ) : ?>
				<?php foreach( $products as $key => $item ) : ?>
									
					<?php if( $key == 0 OR $key == 1) : ?>
						<?php $key1 = 0; $key2 = 1 ; ?>
						<?php include("eshop/product-list.33-66.view.php"); 	?>
					<?php elseif( $key == 2 OR $key == 3  ) : ?>	
						<?php $key1 = 2; $key2 = 3 ; ?>
						<?php include("eshop/product-list.66-33.view.php"); 	?>	
					<?php elseif( $key == 4 OR $key == 5 OR $key == 6 OR $key == 7 OR $key == 8 OR $key == 9 OR $key >= 14 ) : ?>
						<?php include("eshop/product-list.33-33-33.view.php"); 	?>
					<?php elseif( $key == 10 OR $key == 11) : ?>
						<?php include("eshop/product-list.66-33.view.php"); 	?>
					<?php elseif( $key == 12 OR $key == 13  ) : ?>	
						<?php $key1 = 12; $key2 = 13 ; ?>
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