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
				<div class="w100 left clear mb3  ">
					
					<?php if($page ) : ?>
						<?=$page['text'] ?>
					<?php endif; ?>
					
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