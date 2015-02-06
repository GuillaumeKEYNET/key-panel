<?

final class truefalse extends field{

	function view(){
		if ($this->value == 1) return "<i class='fa fa-check' ></i>"; 
		else return "";
	}
	function bake_field (){
    	$output="<br />";
		$output .= "<input type='checkbox' name='".$this->fieldname."' id='".$this->fieldname."' value='1' ";
		if (!isset($this->value) or $this->value != 0) $output .= 'checked';
						$output .= ">";
        return $output;	
						
						
	}
		
	function exec_add () {
		return $this->value;
	}
	function exec_edit () {
		return $this->value;	
	}

}

