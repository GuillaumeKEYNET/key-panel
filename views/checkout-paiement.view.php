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
				<div class="w80 center clear mb3  ">
					
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					<!-- TUNNEL ARIANE -->
					<?php include("eshop/checkout-ariane.view.php"); 	?>
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					
					<div class=" txtcenter">Référence Commande <?= $reference ?></div>
					
					<!-- ................. -->
					<!-- PAYMENT -->
					<?php include("payment/".$payment.".view.php"); 	?>
					<!-- ................. -->
					
				</div>
			</div>
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		</div>
		
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER -->
		<?php include("includes/footer.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
	
	</body>
</html>
