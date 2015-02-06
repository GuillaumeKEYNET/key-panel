<?php

final class multiselect extends field{

	//*******************************************************************
	function view()
	{
		//GET PARENT / REFERENCE TABLE
		$parent_table = str_replace("_id","",$this->fieldname);
		
		$output = "";
		
		if ($this->value != ''){
			$datas = explode(",",$this->value);
			$output = '';
			$f_fieldname = str_replace("_id","",$this->fieldname);
			$i = 0;
			foreach($datas as $data):
				if ($i > 0) $output .= ",";			
				$output .= $this->get_value( $parent_table , $data );

				$i++;
			endforeach; 
		return $output;
		}

		return '';
		
		// return $this->get_value( $parent_table , $this->value );
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
		$output .= "<select multiple='multiple' name='".$this->fieldname."[]' id='".$this->fieldname."' class='form-control'  size='6'  >";
		// $output .= "<option value=''>---</option>";
		
		foreach( $data as $item )
		{
			$field_value = '' ;
			foreach( $item as $key => $field )
			{
				if (is_string($field) and $field != '0' and intval($field) == 0 ) 
				{
					$field_value = $field;
				}
			}
			
			//BAKE SELECT OPTION
			$output .= "<option value='".$item['id']."' ";
			//selected ?
			if ( in_array($item['id'] , explode(",",$this->value) ) ) 
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
	function get_processed () 
	{
		// var_dump( implode(",",$this->value) );exit;
		
		if (is_array($this->value))
			return implode(",",$this->value).',';
		else
			return '';	
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
				if (is_string($field) and $field != '0' and intval($field) == 0 ) 
					return $field;
			}
		}
		else
		{
			return '';
		}
	
	}
	
	



}

