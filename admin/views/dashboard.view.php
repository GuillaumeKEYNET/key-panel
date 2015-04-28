<!DOCTYPE html>
<html lang="en">

	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	<!-- HTML_HEADER -->
	<?php include("global/meta.view.php"); 	?>
	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	
<body>

    <div id="wrapper">

        <!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- HEADER -->
		<?php include("global/header.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
        <div id="page-wrapper">
            <div class="row">
                <div class="col-lg-12">
                    <h1 class="page-header">Dashboard</h1>
                </div>
                <!-- /.col-lg-12 -->
            </div>
            <!-- /.row -->
            <div class="row">
                
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					<!-- NOTIFICATION SMS -->
					<?php if( isset( $flash['info'] )) : ?>
						<div class="alert alert-info alert-dismissable" style="">
							<?= $flash['info'] ?>
							<button aria-hidden="true" data-dismiss="alert" class="close" type="button">×</button>
						</div>
					<?php endif; ?>
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
				
				
				<div class="col-lg-3 col-md-6">
                    <div class="panel panel-yellow">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-shopping-cart fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge"><?= $stats['orders'] ?></div>
                                    <div>Nouvelles commandes!</div>
                                </div>
                            </div>
                        </div>
                        <a href="<?= URL ?>/show/eshop_order">
                            <div class="panel-footer">
                                <span class="pull-left">View Details</span>
                                <span class="pull-right"><i class="fa fa-arrow-circle-right"></i></span>
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>
               
			   <div class="col-lg-3 col-md-6">
                    <div class="panel panel-primary">
                        <div class="panel-heading">
                            <div class="row">
                                <div class="col-xs-3">
                                    <i class="fa fa-newspaper-o fa-5x"></i>
                                </div>
                                <div class="col-xs-9 text-right">
                                    <div class="huge"><?= $stats['pageviews'] ?></div>
                                    <div>Pages Vues</div>
                                </div>
                            </div>
                        </div>
                        <a href="#">
                            <div class="panel-footer">
                                <div class="clearfix"></div>
                            </div>
                        </a>
                    </div>
                </div>
                
				<div class="col-lg-12">
                    <div class="panel panel-default">
                        <div class="panel-heading">
                            Visites sur le dernier mois : <?= $stats['visits'] ?>
                        </div>
                        <!-- /.panel-heading -->
                        <div class="panel-body">
                           <canvas id="sessionsChart" class=" " width="600" height="150" style="width: 98% !important; " ></canvas>
                        </div>
                        <!-- /.panel-body -->
                    </div>
                    <!-- /.panel -->
                </div>
				
				<script src="<?= URL ?>/assets/js/chart.min.js"></script>
				<script>
					
					$( function(){
						
						// Get the context of the canvas element we want to select
						var ctx = document.getElementById("sessionsChart").getContext("2d");
						
						//DATA CHART
						var data = {
							labels: <?= json_encode(  $labels ) ?>,
							// labels: [] ,
							datasets: [
								{
									label: "Courbe de poids",
									fillColor: "rgba(150, 200, 200, 0.3)",
									strokeColor: "#099",
									pointColor: "#099",
									pointStrokeColor: "#fff",
									pointHighlightFill: "#fff",
									pointHighlightStroke: "rgba(151,187,205,1)",
									data: <?= json_encode( $values ) ?>
								}
							]
						};
						//OPTION CHART
						var options = {
							showScale: true,
							scaleLabel: "<%=value%>",
							scaleShowLabels: true,
							pointDot : true , 
							showTooltips: true,
							legendTemplate : " " , 
							responsive: false,
							// scaleOverride: true, 
							// scaleStartValue: 0, 
							// scaleStepWidth: 5, 
							// scaleSteps: 25
						} ;

						//CREATE CHART
						var weightChart = new Chart(ctx).Line(data, options);
					
					});
						
					
					
				</script>
			
			</div>
            <!-- /.row -->
            <div class="row">
               
            </div>
            <!-- /.row -->
        </div>
        <!-- /#page-wrapper -->

		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER -->
		<?php include("global/footer.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
    </div>
    <!-- /#wrapper -->

  

</body>

</html>
