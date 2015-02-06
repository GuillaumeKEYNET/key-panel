<?


final  class textarea extends field{

	function view(){
		return  substr(strip_tags($this->value),0,100)."...";
	}
	function bake_field (){
		return "<textarea class='form-control ' rows=\"5\" id=\"".$this->fieldname."\" name=\"".$this->fieldname."\"  >".$this->value."</textarea>";				
	}
		
	function get_processed () {
		return $this->value;		
	}
	
}

							