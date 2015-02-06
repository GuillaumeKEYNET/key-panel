<?



final class literal extends field{

	function view(){
		return $this->value;
	}
	function bake_field (){
		return '<input  type="text" class="form-control" name="'.$this->fieldname.'" id="'.$this->fieldname.'" placeholder="'.$this->placeholder.'" value="'.trim($this->value).'" >';				
	}
		
	function get_processed () {
		return (stripslashes($this->value));

	}
	
	
}

