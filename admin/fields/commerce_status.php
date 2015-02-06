<?


final class commerce_status extends field{

	var $options = array( 'non payé' , 'payé' , 'envoyé' , 'annulé' , 'error'  );  
	
	function view() 
	{
		$output = $this->value ;
		return $output ;
		// return $this->value ;
	}
	function bake_field (){
		$output = "<select id=\"".$this->fieldname."\" name=\"".$this->fieldname."\" class='form-control' >";
				
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

