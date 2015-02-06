<?

final class slug extends field{

	function view(){
		return $this->value;
	}
	function bake_field (){
		$out = '';
		if ($this->value == ''){
			$out = '<script>$(document).ready(function(){ $("#'.$this->fieldname.'").val($("#'.$this->slug_reference.'").val()); validateSlug("'.$this->fieldname.'");});</script>';
		
		} 
			$out .= '<script>$(document).ready(function(){ $("#'.$this->slug_reference.'").change(function(){ $("#'.$this->fieldname.'").val($("#'.$this->slug_reference.'").val()); validateSlug("'.$this->fieldname.'");}); });</script>';
		
		return "<input  type=\"text\"  onChange=\"validateSlug('".$this->fieldname."');\" class='form-control' name=\"".$this->fieldname."\" id=\"".$this->fieldname."\" value=\"".trim($this->value)."\"  style='background: #ddd;' >".$out;

		
	}
		
	function exec_add () {
		return $this->value;
	}
	function exec_edit () {
		return $this->value;	
	}

}



