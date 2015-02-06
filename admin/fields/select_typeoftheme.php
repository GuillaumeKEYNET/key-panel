<?

final class select_typeoftheme extends field{

	var $options = array( 'Thème' , 'Pack'  );  
	
	function view() 
	{
		$output = $this->value ;
		return $output ;
		// return $this->value ;
	}
	function bake_field (){
		$output = "<select id=\"".$this->fieldname."\" name=\"".$this->fieldname."\"  class='form-control '>";
				
			foreach( $this->options as $option )
			{
				$selected = ( $option == $this->value )?  "selected='selected'" : ' ' ;
				$output .= "<option value='".$option."' ".$selected."' >".$option."</option>  ";
			}

		
		$output .= 	"</select>";
        return $output;
	}
		
	function exec_add () {
		return $this->value;
	}
	function exec_edit () {
		return $this->value;	
	}




}

