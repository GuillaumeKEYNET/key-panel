<?


final class commerce_html extends field{

	function view(){
	if ($this->value != '')
		return  substr(strip_tags($this->value),0,100)."...";
		return '';
	}
	function bake_field (){
		return "<div class='span6'>".$this->value."</div><br /><textarea style='display: none;width:0px; height:0px;' name='".$this->fieldname."' >".$this->value."</textarea>";
	}
		
	function get_processed () {
		
		return ($this->value);
		
	
	}

}

							