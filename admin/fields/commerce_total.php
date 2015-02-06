<?


final class commerce_total extends field{

	function view(){
	if ($this->value != '')
		return  number_format( $this->value , 2 )." €";
		return '';
	}
	function bake_field (){
		return "<div class='span6' style='font-weight: 700; font-size: 18px; font color: #440000;'>".number_format( $this->value , 2 )." €</div><br /><input type='hidden' name=\"".$this->fieldname."\" value=\"".$this->value."\"/>";
	}
		
	function get_processed()
	{
		return $this->value;
	}

}

							