			
			
			 <div class="navbar-default sidebar" role="navigation">
                <div class="sidebar-nav navbar-collapse">
                    <ul class="nav" id="side-menu">
                       
                       <?php /* FOReACH */ foreach( $menu as $item ) : ?>
					   
					    <li>
                            <a class=" " <?= (@$item['url'])? 'href="'.URL.@$item['url'].'"' : ''; ?> >
								<i class="fa <?= @$item['icon'] ?>  fa-fw "></i> <?= @$item['text'] ?>
								<?php /* IF */ if( @$item['items'] ) : ?>
								<span class="fa arrow"></span>
								<?php /* END IF? */ endif; ?>
							</a>
							
							<?php /* IF */ if( @$item['items'] ) : ?>
							<ul class="nav nav-second-level">
								<?php /* FOReACH */ foreach( @$item['items'] as $submenu ) : ?>
								<li>
									<a class="active" <?= (@$submenu['url'])? 'href="'.URL.@$submenu['url'].'"' : ''; ?> ><i class="fa <?= @$submenu['icon'] ?>  fa-fw "></i> <?= @$submenu['text'] ?></a>
								</li>
								<?php /* END FOReACHE? */ endforeach; ?>
							</ul>
							<?php /* END IF? */ endif; ?>
							
                        </li>
					   
					   <?php /* END FOReACHE? */ endforeach; ?>
					   
					 
                    </ul>
                </div>
                <!-- /.sidebar-collapse -->
            </div>
            <!-- /.navbar-static-side -->