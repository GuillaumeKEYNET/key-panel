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
                    <h1 class="page-header"><?= $table['label'] ?></h1>
                </div>
                <!-- /.col-lg-12 -->
            </div>
            <!-- /.row -->
            <div class="row">
                <div class="col-lg-12">
                   
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					<!-- NOTIFICATION SMS -->
					<?php if( isset( $flash['update'] )) : ?>
						<div class="alert alert-success alert-dismissable" style="">
							Item Updated
							<button aria-hidden="true" data-dismiss="alert" class="close" type="button">×</button>
						</div>
					<?php endif; ?>
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					<!-- NOTIFICATION DELETE -->
					<?php if( isset( $flash['delete'] )) : ?>
						<div class="alert alert-warning alert-dismissable" style="">
							Item deleted
							<button aria-hidden="true" data-dismiss="alert" class="close" type="button">×</button>
						</div>
					<?php endif; ?>
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
				   
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					<!-- ADD BUTTON -->
					<?php if(!@$table['no_add']): ?>
						<a class="btn btn-success" href="<?= URL ?>/show/<?= $table['name'] ?>/-1"><i class="fa fa-plus "></i> Add New</a><br />
					<?php endif; ?>
					<!-- +++++++++++++++++++++++++++++++++++++++ -->
					
					<div class="table-responsive">
						<table class="table table-striped   table-hover" id="dataTables-example">
							<thead>
								<tr>
									<?php /* FOReACH fields*/ foreach( @$table['fields'] as $field ) : if( @$field['show'] ) : ?>
									<th><?= $field['label'] ?></th>
									<?php /* END FOReACHE? fields */ endif;endforeach; ?>
									<th width="120"></th>
								</tr>
							</thead>
							<tbody id="<?= (@$table['sortable'])? 'sortable' : '' ; ?>">
								
								<!-- +++++++++++++++++++++++++++++++++++++++ -->
								<?php /* FOReACH */ if( $data ) foreach( $data as $item ) : ?>
								<tr class=" " data-id="<?= $item['id'] ?>" >
									<?php /* FOReACH fields*/ foreach( $table['fields'] as $field ) : if( @$field['show'] ) : ?>
									<td>
										<?php
											$object = new $field['type'](array(
												'table' 	=> 	@$table['table'] ,
												'rid' 		=> 	@$item['id'] ,
												'label' 	=> 	@$field['label'] ,
												'fieldname' => 	@$field['name'] ,
												'value' 	=> 	@$item[$field['name']] ,
												'placeholder' => 	@$field['placeholder'] ,
											))  ; 
											
											echo $object->view();
										?>
									
									</td>
									<?php /* END FOReACHE? fields */ endif;endforeach; ?>
									<td class="right">
										<!-- +++++++++++++++++++++++++++++++++++++++ -->
										<!-- ACTIONS BUTTONS -->
										<a href="<?= URL ?>/show/<?= $table['name'] ?>/<?= $item['id'] ?>" class="btn btn-info  " ><i class="fa fa-pencil"></i> <? if( @$table['child'] ) { ?><i class="fa fa-list"></i><? } ?></a>
										<?php if(!@$table['no_add']): ?><a href="<?= URL ?>/delete/<?= $table['name'] ?>/<?= $item['id'] ?>" class="btn btn-default delete_link  "  ><i class="fa fa-trash-o"></i></a><?php endif; ?>
										<?php if(@$table['sortable']): ?><span  class="handle" ><i class="fa fa-sort"></i></span><?php endif; ?>
										<!-- +++++++++++++++++++++++++++++++++++++++ -->
									</td>
								</tr>
								<?php /* END FOReACHE? */ endforeach; ?>
								<!-- +++++++++++++++++++++++++++++++++++++++ -->
								
								
								
							</tbody>
						</table>
					</div>
					<!-- /.table-responsive -->
                       
                   
                </div>
                <!-- /.col-lg-6 -->
               
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
	
	


   <?php /*
    <!-- DataTables JavaScript -->
    <script src="<?= URL ?>/assets/js/plugins/dataTables/jquery.dataTables.js"></script>
    <script src="<?= URL ?>/assets/js/plugins/dataTables/dataTables.bootstrap.js"></script>
	*/ ?>

    <!-- Page-Level Demo Scripts - Tables - Use for reference -->
    <script>
    $(document).ready(function() {
        $('#sortable').sortable({ 
			cursor: "move",
			forcePlaceholderSize: true ,
			// handle: ".handle" , 
			cursorAt: { left: 25 , top: 25 } ,
			update : function(){
				$('#sortable').children().each( function(){
					$.post( "<?= URL ?>/update-field/<?= $table['table'] ?>/"+$(this).data('id'), { orden: $(this).index() } );
				});
				
			}
		});
		
		$('.delete_link').click( function(e){
			
			if( confirm('Confirm delete') )
			{
				$.get( $(this).attr('href') );
				$(this).parent().parent().fadeOut( 1000 , function() { $(this).remove(); } );
			}
			e.preventDefault();
			return false;
			
			
		});
		
    });
    </script>
	

</body>

</html>
