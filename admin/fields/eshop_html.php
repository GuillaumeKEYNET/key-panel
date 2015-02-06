<?


final class eshop_html extends field{

	function view(){
	if ($this->value != '')
		return  substr(strip_tags($this->value),0,100)."...";
		return '';
	}
	function bake_field (){
		return "<div style='display: block; width: 100%; float: left; clear: both; border: 1px dashed grey; padding: 10px; margin: 0 0 10px 0;'>".$this->value."</div><br /><textarea style='display: none;width:0px; height:0px;' name='".$this->fieldname."' >".$this->value."</textarea>";
	}
		
	function get_processed () {
		
		return ($this->value);
		
	
	}

}

							