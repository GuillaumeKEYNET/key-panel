<?

final class visible extends field{

	function view(){
		$output="";
		$output .= "<input type='checkbox' onchange=' $.post( \"".URL."/update-field/".$this->table."/".$this->rid."?".$this->fieldname."=\"+(this.checked? 1 : 0) );;' name='".$this->fieldname."' id='".$this->fieldname."'   ";
		if ( $this->value != 0) $output .= 'checked';
		$output .= ">";
        return $output;	
	}
	
	function bake_field (){
    	$output="<br />";
		$output .= "<input type='checkbox' name='".$this->fieldname."' id='".$this->fieldname."' value='1' ";
		if (!isset($this->value) or $this->value != 0) $output .= 'checked';
		$output .= ">";
		$output .= "";
        return $output;					
	}
		
	function get_processed () {
		return $this->value;
	}

}

