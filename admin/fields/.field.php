<?php

abstract class field{
	
	abstract protected function view();
	abstract protected function bake_field();
	// abstract protected function get_processed();
	// abstract protected function exec_add();
	// abstract protected function exec_edit();
		
	public $fieldname;
	public $type;
	public $value;
	public $label;
	public $rid;
	public $table;
	
   // protected $db;
   
   // public final function __construct($fieldname,$label,$type,$value,$table = -1,$rid = -1){
   public final function __construct($params){
		
		foreach( $params as $key => $param )
		{
			$this->$key = $param;
		}
		
   } 
   
	public  function get_processed(){
		return $this->exec_add();
	
	
	}
	
	
}

//INCLUDE FIELDS TYPES
include "combo.php";
include "combo_disabled.php";
include "date.php";
include "disabled.php";
include "file_img.php";
include "literal.php";
include "select_size.php";
include "slug.php";
include "textarea.php";
include "truefalse.php";
include "visible.php";
include "wysiwyg.php";

include "number.php";
include "select_typeoftheme.php";
include "select_typeofconsult.php";
include "eshop_status.php";
include "eshop_total.php";
include "eshop_html.php";
include "eshop_address.php";


// include "parent_id.php";
// include "url.php";

// include "featured.php";
// include "hora.php";
// include "color.php";
// include "combo_child.php";
// include "youtube.php";
// include "email.php";
// include "dias_semana.php";
// include "fecha.php";
// include "file_file.php";
// include "float.php";
// include "mp3.php";
// include "multiselect.php";
// include "number.php";
// include "number_slider.php";
// include "number_slider_speed.php";
// include "password.php";
// include "percent.php";
// include "select_color.php";
// include "select_position.php";
// include "tags.php";;

