<?

final class select_size extends field{

	var $options = array( 'simple' , 'double' );
	
	function view()
	{
		return $this->value ;
	}
	function bake_field (){
		$output = "<select id='".$this->fieldname."' name='".$this->fieldname."' class='form-control' >";
				
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

