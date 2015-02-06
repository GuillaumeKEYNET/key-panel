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
                    <h1 class="page-header"><?= $table['label'] ?> > <?= ( $data )? '<i class="fa fa-pencil "></i> EDIT' : '<i class="fa fa-plus "></i> ADD' ; ?></h1>
                </div>
                <!-- /.col-lg-12 -->
            </div>
            <!-- /.row -->
            <div class="row">
                
				
				<?php
					// SET ITEM 
					$item = $data;
					
					//BACK LINK if table is child
					if( @$table['parent'] )
						$back_link = "/show/".$table['parent']."/".$item['parent_id'] ; 
					else
						$back_link = "/show/".$table['name'] ;
					
				?>
				
				<form id="form" role="form" action="<?= URL ?>/update/<?= $table['name'] ?>/<?= @$item['id'] ?>" method="POST" enctype="multipart/form-data" >
					
					<div class="col-md-8 clear left">
						<button type="submit" class="btn btn-success"><i class="fa fa-pencil"></i> SAVE </button>
						<a class="btn btn-default" href="<?= URL.$back_link ?>"><i class="fa fa-chevron-left "></i> Back</a>
						<br /><br />
					</div>
					
					<?php /* FOReACH fields*/ foreach( $table['fields'] as $field ) :   ?>
						
						<div class="<?= (@$field['style'])? $field['style'] : 'col-md-8 ' ?>">
					
							<div class="form-group">
								<label><?= @$field['label'] ?></label>
								<?php
									$object = new $field['type'](array(
										'label' 	=> 	@$field['label'] ,
										'fieldname' => 	@$field['name'] ,
										'value' 	=> 	@$item[$field['name']] ,
										'placeholder' => 	@$field['placeholder'] ,
										'combo_order' => 	@$field['combo_order'] ,
										'slug_reference' => 	@$field['slug_reference'] ,
									))  ; 
									
									echo $object->bake_field();
								?>
								<p class="help-block"><?= @$field['help'] ?></p>
							</div>
						
						</div>
						
						<?php /* END FOReACHE? */ endforeach; ?>
						
						<div class="col-md-8 clear left">
							<button type="submit" class="btn btn-success"><i class="fa fa-pencil"></i> SAVE</button>
							<a class="btn btn-default" href="<?= URL.$back_link ?>"><i class="fa fa-chevron-left "></i> Back</a>
							<br /><br />
						</div>
					
						
				</form>
			</div>
		
			<br />
			
			
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			<!-- CHILD TABLE -->
			<?php include("list-children.view.php"); 	?>
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			
			
			
		</div>
	</div>
		
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		<!-- FOOTER -->
		<?php include("global/footer.view.php"); 	?>
		<!-- +++++++++++++++++++++++++++++++++++++++ -->
		
		
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		<!-- TINYMCE WYSIWYG  -->
		<script src="<?= URL ?>/assets/js/tinymce/tinymce.min.js"></script>
		<script>
			$(function() {
				$('textarea.tinymce').tinymce({
					plugins: 'textcolor,media,code,image,link',
					theme : "modern",
					content_css : "<?= URL ?>/assets/js/tinymce/content.css?" + new Date().getTime(),
					height: "300",
					relative_urls: false,
					menubar : false , 
					statusbar: false,
						// toolbar: [ "styleselect forecolor backcolor bullist | bold italic | link unlink media image | alignleft aligncenter alignright | code " ]
					toolbar: [ "alignleft aligncenter alignright | bold italic | forecolor backcolor bullist | link unlink media image | code removeformat  " ] ,
					file_browser_callback: custom_file_browse ,
					
				});
			});
		</script>
		
		<!-- CUSTOM FILE UPLOADER  -->
		<script>
			custom_file_field = false;
			function custom_file_browse(field_name, url, type, win)
			{  
				if( type == 'image' )
				{
					custom_file_field = win.document.getElementById(field_name) ; 
					$('#custom_file_form input').click();  
				}
			}
			$(function() {
				//AJAX SUBMIT FILE MANAGER
				$( '#custom_file_form' ).submit( function( e ) {
					custom_file_field.value = "loading ...";
					myApp.showPleaseWait();
					
					$.ajax( {
						url: '<?= URL ?>/upload/image',
						type: 'POST',
						data: new FormData( this ),
						processData: false,
						contentType: false,
						success : function(data){
							custom_file_field.value = data ;
							myApp.hidePleaseWait();
							// $("body").append("<img src='" + data +"' style='width: 200px; position: fixed; top: 20%; right: 10%;'/>" );
						}
					} );
					e.preventDefault();
				} );
				
				
			});
		</script>	
		<form id="custom_file_form" action="#" target="form_target" method="post" enctype="multipart/form-data" style="width:0px;height:0;overflow:hidden">
			<input name="uploads" type="file" onchange="$('#custom_file_form').submit();this.value='';">
		</form>
		
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		<!-- FILES IMG FUNCTION  -->
		<script>
			function DeleteFile( fieldName , fileName )
			{
				if( confirm('Delete this file ?') )
				{
					$.post( "<?= URL ?>/update-field/<?= $table['table'] ?>/<?= $item['id'] ?>?"+fieldName+"=" );
					$.get( "<?= URL ?>/remove-image?file_img="+fileName );
					$('#'+fieldName+"_div").remove();
					$('#'+fieldName).slideDown().css('display','block');
					fieldName.value="";
				}
			}
		</script>
		
		
		
		
		
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		<!-- GLOBAL FUNCTION  -->
		<script>	
			$(function() {
				
				$('#form').submit( function(){
					myApp.showPleaseWait();
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
		<!-- +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++  -->
		
		
		
</body>

</html>
