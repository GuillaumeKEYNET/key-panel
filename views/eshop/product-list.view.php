		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->
		<div class="w100 left clear mb3   ">
		<?php if(sizeof( $products ) > 0 ) : ?>
		<?php foreach( $products as $key => $item ) : ?>
							
			<?php if( $key == 0 ) : ?> 
			<!-- +++++++++++++++++++++++++ -->
			<!-- 50 /50 text  --> 
			
			<?php endif; ?>
			
			<?php if( $key == 1 OR $key == 2 OR $key == 3 OR $key == 7 OR $key == 8 OR $key == 9 OR $key == 12 OR $key == 13 OR $key == 14 ) : ?>
			<!-- +++++++++++++++++++++++++ --> 
			<!-- 33 / 33 / 33  --> 
			
			<?php endif; ?>
			
			<?php if( $key == 4 ) : ?>			
			<!-- SI ACCUEIL.NUM_LIGNE egal 4 -->	
			<!-- +++++++++++++++++++++++++ -->
			<!-- 33 text / 66  -->
			<?php endif; ?>
			
			<?php if( $key == 5 OR $key == 6 OR $key == 10 OR $key == 11  ) : ?>	
			<!-- SI ACCUEIL.NUM_LIGNE egal 5 ou ACCUEIL.NUM_LIGNE egal 6 ou ACCUEIL.NUM_LIGNE egal 10 ou ACCUEIL.NUM_LIGNE egal 11 -->	
			<!-- +++++++++++++++++++++++++ -->
			<!-- 50 /50  -->
			
			<?php endif; ?>
			
			<?php if( $key == 15 OR $key == 16  ) : ?>	
			<?php $key1 = 15; $key2 = 16 ; ?>
			<!-- +++++++++++++++++++++++++ -->
			<!-- 66 /33   -->
			<!-- SI ACCUEIL.NUM_LIGNE egal 15 -->	
			
			<?php endif; ?>
			
		
		<?php endforeach ; ?>
		<?php endif ; ?>
		
		</div>
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++ -->