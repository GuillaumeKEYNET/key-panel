<?



final class disabled extends field{

	function view(){
		return $this->value;
	}
	function bake_field (){
		return "<input  type=\"text\" class='form-control disabled' name=\"".$this->fieldname."\" id=\"".$this->fieldname."\" value=\"".trim($this->value)."\" enabled='false' style='background: #ddd;' readonly >";				
	}
		
	function get_processed () {
		return $this->value;
	}

}

