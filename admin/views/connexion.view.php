<!DOCTYPE html>
<html lang="en">

	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	<!-- HTML_HEADER -->
	<?php include("global/meta.view.php"); 	?>
	<!-- +++++++++++++++++++++++++++++++++++++++ -->

<body>

    <div class="container">
        <div class="row">
            <div class="col-md-4 col-md-offset-4">
                <div class="login-panel panel panel-default">
                    <div class="panel-heading">
                        <h3 class="panel-title">Please Sign In</h3>
                    </div>
                    <div class="panel-body">
                        <form role="form" method="post" action="<?= URL ?>/connexion">
                            <fieldset>
                                <div class="form-group">
                                    <input class="form-control" placeholder="Login" name="login" type="text" autofocus>
                                </div>
                                <div class="form-group">
                                    <input class="form-control" placeholder="Password" name="sesame" type="password" value="">
                                </div>
                                
                                <!-- Change this to a button or input when using this as a form -->
                                <input type="submit" class="btn btn-lg btn-success btn-block" text="OK" />
                            </fieldset>
                        </form>
						
						<!-- +++++++++++++++++++++++++++++++++++++++ -->
						<!-- NOTIFICATION -->
						<?php if( isset( $flash['error'] )) : ?>
							<div class="alert alert-danger alert-dismissable" style="margin-top: 15px; ">
								<?= $flash['error'] ?>
								<button aria-hidden="true" data-dismiss="alert" class="close" type="button">×</button>
							</div>
						<?php endif; ?>
						<?php if( isset( $flash['info'] )) : ?>
							<div class="alert alert-info alert-dismissable" style="margin-top: 15px; ">
								<?= $flash['info'] ?>
								<button aria-hidden="true" data-dismiss="alert" class="close" type="button">×</button>
							</div>
						<?php endif; ?>
						<!-- +++++++++++++++++++++++++++++++++++++++ -->
						
                    </div>
                </div>
            </div>
        </div>
    </div>
	
	<!-- +++++++++++++++++++++++++++++++++++++++ -->
	<!-- FOOTER -->
	<?php include("global/footer.view.php"); 	?>
	<!-- +++++++++++++++++++++++++++++++++++++++ -->

   

</body>

</html>
