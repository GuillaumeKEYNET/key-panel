<?php

final class combo extends field{

	//*******************************************************************
	function view()
	{
		//GET PARENT / REFERENCE TABLE
		$parent_table = str_replace("_id","",$this->fieldname);
		return $this->get_value( $parent_table , $this->value );
	}
	
	//*******************************************************************
	function bake_field ()
	{
		//GET PARENT / REFERENCE TABLE
		$parent_table = str_replace("_id","",$this->fieldname);
		
		global $app ;
		//GET REFERENCE
		$data = $app->database->select( $parent_table  , '*' , array( 'ORDER' => $this->combo_order ) );
		
		$output = "<div id='combo_".$this->fieldname."' >";
		$output .= "<select name='".$this->fieldname."' id='".$this->fieldname."' class='form-control' >";
		$output .= "<option value='-1'>---</option>";
		
		foreach( $data as $item )
		{
			$field_value = '' ;
			foreach( $item as $key => $field )
			{
				// if (is_string($field) and $field != '0' and intval($field) == 0 ) 
				if ( is_string($field) && $key != 'id' && $key != 'orden' ) 
				{
					$field_value = $field;
					break;
				}
			}
			
			//BAKE SELECT OPTION
			$output .= "<option value='".$item['id']."' ";
			//selected ?
			if ( $item['id'] == $this->value ) 
				$output .= " selected";
			$output .=">";
			$output .= $field_value;
			$output .= "</option>";
			
		}
		$output .= "</select>";
		$output .= "</div>";
		
        return $output;
	}
	
	//*******************************************************************
	function get_processed () {
		return $this->value;	
	}
	
	//*******************************************************************
	//GET REFERENCED VALUE
	function get_value( $parent_table , $id )
	{
		global $app ;
		//GET REFERENCE
		$item = $app->database->get( $parent_table  , '*' , array( 'id' => $id ) );
		
		if( $item )
		{
			foreach( $item as $key => $field )
			{
				// if (is_string($field) and $field != '0' and intval($field) == 0 ) 
				if ( is_string($field) && $key != 'id' && $key != 'orden' ) 
					return $field;
			}
		}
		else
		{
			return '--';
		}
	
	}
	
	



}

