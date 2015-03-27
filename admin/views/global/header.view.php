		
		
			<!-- Navigation -->
        <nav class="navbar navbar-default navbar-static-top" role="navigation" style="margin-bottom: 0">
            <div class="navbar-header">
                <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
                    <span class="sr-only">Toggle navigation</span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                    <span class="icon-bar"></span>
                </button>
                <a class="navbar-brand" href="<?= URL ?>">
					<?= APP_NAME ?>
				</a>
            </div>
            <!-- /.navbar-header -->

            <ul class="nav navbar-top-links navbar-right">
                <li class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">
                        <i class="fa fa-gear fa-fw"></i>  <i class="fa fa-caret-down"></i>
                    </a>
                    <ul class="dropdown-menu dropdown-user">
                        <li> 
							<a><i class="fa fa-user fa-fw"></i> <?= $_SESSION['user']['login'] ?></a>
						</li>
						<li>
							<a class="" title="Voir le site" href="<?= APP_URL ?>" target="_blank" ><i class="fa fa-eye fa-fw"></i> See website</a>
                        </li>
                        <li class="divider"></li>
                        <li><a href="<?= URL ?>/deconnexion"><i class="fa fa-sign-out fa-fw"></i> Logout</a>
                        </li>
                    </ul>
                    <!-- /.dropdown-user -->
                </li>
                <!-- /.dropdown -->
            </ul>
            <!-- /.navbar-top-links -->

           <!-- +++++++++++++++++++++++++++++++++++++++ -->
			<!-- HTML_HEADER -->
			<?php include("menu.view.php"); 	?>
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
        </nav>
