		<?php if(  $table_child && $data ) : ?>
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
			
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
			<div class="row" >
				<div class="col-lg-12">
					<hr />
				   <h2 class="page-header">
						<?= $table_child['label'] ?> 
						<button type="button" class=" btn btn-warning" data-toggle="collapse" data-target="#list_children" aria-expanded="true" aria-controls="demo">
							<i class="fa fa-list" ></i>
						</button>
					
					</h2>
					
					
                </div>
            </div>
			
			<div id="list_children" class="row collapse <?= ( isset( $flash['update'] ))?'in'  : '';  ?>" >
				
				<!-- +++++++++++++++++++++++++++++++++++++++ -->
				<!-- NOTIFICATION SMS -->
				<?php if( isset( $flash['update'] )) : ?>
				<div class="col-lg-12">
					<div class="alert alert-success alert-dismissable" style="">
						Item Updated
						<button aria-hidden="true" data-dismiss="alert" class="close" type="button">×</button>
					</div>
				</div>
				<?php endif; ?>
				<!-- +++++++++++++++++++++++++++++++++++++++ -->
				
				
				<!-- +++++++++++++++++++++++++++++++++++++++ -->
				<!-- ADD BUTTON -->
				<div class="col-lg-12">
					<?php if(!@$table_child['no_add']): ?>
						<a class="btn btn-success" href="<?= URL ?>/show/<?= $table_child['name'] ?>/-1?parent_id=<?= $item['id']?>"><i class="fa fa-plus "></i> Add New</a><br />
					<?php endif; ?>
				</div>
				<!-- +++++++++++++++++++++++++++++++++++++++ -->
				
				<div class="col-lg-12">
					<div class="table-responsive">
						<table class="table table-striped   table-hover" id="dataTables-example">
							<thead>
								<tr>
									<?php /* FOReACH fields*/ foreach( $table_child['fields'] as $field ) : if( @$field['show'] ) : ?>
									<th><?= $field['label'] ?></th>
									<?php /* END FOReACHE? fields */ endif;endforeach; ?>
									<th width="120"></th>
								</tr>
							</thead>
							<tbody id="<?= (@$table_child['sortable'])? 'sortable' : '' ; ?>">
								
								<!-- +++++++++++++++++++++++++++++++++++++++ -->
								<?php /* FOReACH */ if( $data_child ) foreach( $data_child as $item ) : ?>
								<tr class=" " data-id="<?= $item['id'] ?>" >
									<?php /* FOReACH fields*/ foreach( $table_child['fields'] as $field ) : if( @$field['show'] ) : ?>
									<td>
										<?php
											$object = new $field['type'](array(
												'table' 	=> 	@$table_child['table'] ,
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
										<a href="<?= URL ?>/show/<?= $table_child['name'] ?>/<?= $item['id'] ?>" class="btn btn-info  " ><i class="fa fa-pencil"></i></a>
										<?php if(!@$table_child['no_add']): ?><a href="<?= URL ?>/delete/<?= $table_child['name'] ?>/<?= $item['id'] ?>" class="btn btn-default delete_link  "  ><i class="fa fa-trash-o"></i></a><?php endif; ?>
										<?php if(@$table_child['sortable']): ?><span  class="handle" ><i class="fa fa-sort"></i></span><?php endif; ?>
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
			</div>
			
			 <script>
				$(document).ready(function() {
					$('#sortable').sortable({ 
						cursor: "move",
						forcePlaceholderSize: true ,
						// handle: ".handle" , 
						cursorAt: { left: 25 , top: 25 } ,
						update : function(){
							$('#sortable').children().each( function(){
								$.post( "<?= URL ?>/update-field/<?= $table_child['table'] ?>/"+$(this).data('id'), { orden: $(this).index() } );
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
			
			<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
			<?php /* END IF TABLE CHILD?  */ endif; ?>	