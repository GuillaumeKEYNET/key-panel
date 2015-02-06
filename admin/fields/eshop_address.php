<?php

final class eshop_address extends field{

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
		$parent_table = 'eshop_order_address' ;
		
		global $app ;
		//GET REFERENCE
		$data = $app->database->get( $parent_table  , '*' , array( 'id' => $this->value ) );
		
		
		$output = "<div style='display: block; width: 100%; float: left; clear: both; border: 1px dashed grey; padding: 10px; margin: 0 0 10px 0; '>";
		
			$output .= $data['civilite'].' '.$data['nom'].' '.$data['prenom'].'<br />';
			$output .= $data['email'].'<br />';
			$output .= $data['tel'].'<br />';
			$output .= $data['adresse'].'<br />';
			$output .= $data['cp'].' '.$data['ville'].' '.$data['pays'].'<br />';
			$output .= $data['infos'].'';
		
		$output .= "</div>";
		$output .= "<input type='hidden' name='".$this->fieldname."' value='".$this->value."' />";
		
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
				if (is_string($field) and $field != '0' and intval($field) == 0 ) 
					return $field;
			}
		}
		else
		{
			return '--';
		}
	
	}
	
	



}

