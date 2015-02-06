<?



final class parent_id extends field{

	function view(){
		return $this->value;
	}
	function bake_field (){
		if(   gett('parent_id') != -1 )		
			return "<input  type=\"text\" class='span1' name=\"".$this->fieldname."\" id=\"".$this->fieldname."\" value=\"".trim(gett('parent_id'))."\">";
		else
			return "<input  type=\"text\" class='span1' name=\"".$this->fieldname."\" id=\"".$this->fieldname."\" value=\"".trim($this->value)."\">";

		

						
	}
		
	function exec_add () {
		return addslashes(stripslashes($this->value));

	}
	function exec_edit () {
		return addslashes(stripslashes($this->value));
	}

}

