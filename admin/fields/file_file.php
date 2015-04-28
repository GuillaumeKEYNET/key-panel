<?
							
final class file_file extends field{

	
	function view(){
		if ($this->value != "")
			return "<a href='".URL."/".PATH."/file/".$this->value."' target='_blank'><i class='fa fa-file-pdf-o'> Fichier : ".$this->value."</i></a>";
			// return "<img style='width:100px' src='".URL."/".PATH."/img/thumbs/".$this->value."'>";
	}
	
	function bake_field (){
				$output="";	
		if ($this->value != "")	
		{				
			$output .= "<div id='".$this->fieldname."_div'>";
			$output .= "<a href='".URL."/".PATH."/file/".$this->value."' target='_blank'><i class='fa fa-file-pdf-o'> Fichier : ".$this->value."</i></a>";
			$output .= "&nbsp; &nbsp; <a href=\"javascript:DeleteFile('".$this->fieldname."','".$this->value."');\"><i class=\"fa fa-trash\" ></i></a>"; 
			$output .= "</div>"; 
			$output.= "<input type=\"file\" id=\"".$this->fieldname."\" name=\"".$this->fieldname."\" style='display: none;'>";
		}// else $output .= "No hay ninguna imagen cargada.<BR>";					
		else
		{
			$output.= "<input type=\"file\" id=\"".$this->fieldname."\" name=\"".$this->fieldname."\">";
		}
		return $output;
	}
		
	function get_processed () 
	{
		
		// echo $this->fieldname." ++ ".$_FILES[$this->fieldname]['name'];
		// echo "<br />";
		
		if ($_FILES[$this->fieldname]['name'] != "")
		{
			//SET RELATIVE UPLOAD PATH
			$relative_path = RELATIVE_PATH."/".PATH."/file"; 
			$file_path = URL."/".PATH."/file"; 
			
			//GET FILE
			$file = $_FILES[$this->fieldname] ;
			
			//MOVE UPLOADED FILE TO PATH
			$file_new_name = strtolower(pathinfo( $file['name'], PATHINFO_FILENAME ).'-'.(date('ymd-His')).".".pathinfo( $file['name'], PATHINFO_EXTENSION) ) ;
			$move_ok = move_uploaded_file( $file['tmp_name'] ,  $relative_path."/".$file_new_name );
		
			//MAKE SOME COPIES
			if ( $move_ok === true) 
			{
				return $file_new_name;
			}
			else
			{
				return '';
			}

		}
		return '';
	}

}

