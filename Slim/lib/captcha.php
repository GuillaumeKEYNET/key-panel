<?php
/******************************************************************************/
/*                                                                            */
/*                       __        ____                                       */
/*                 ___  / /  ___  / __/__  __ _____________ ___               */
/*                / _ \/ _ \/ _ \_\ \/ _ \/ // / __/ __/ -_|_-<               */
/*               / .__/_//_/ .__/___/\___/\_,_/_/  \__/\__/___/               */
/*              /_/       /_/                                                 */
/*                                                                            */
/*                                                                            */
/******************************************************************************/
/*                                                                            */
/* Titre          : Captcha anti-spam simple et avec image                    */
/*                                                                            */
/* URL            : http://www.phpsources.org/scripts423-PHP.htm              */
/* Auteur         : Mhdi                                                      */
/* Date édition   : 02-07-2008                                                */
/*                                                                            */
/******************************************************************************/

session_start(); //Démarrer les sessions

//on crée une image vierge de dimensions 200*50
$image = imagecreate(200,50);

//Les polices  disponibles
$font1 = './2.ttf';
$font2 = './2.ttf';

// La taille de la police
$fontsize = 23;
//Les couleurs
$blanc = imagecolorallocate($image, 250, 250, 250);//Couleur blanche
$gris = imagecolorallocate($image, 0, 0, 0);//couleur grise
$noir = imagecolorallocate($image, 79, 79, 79);//Couleur noire

//Les coordonnées
$z=35;
$y=35;

//Les caractères pouvant être inscrits dans l'image
$txt=array("A","B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", 
"M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
 "1", "2", "3", "4", "5", "6", "7", "8", "9");

//Boucle qui permet d'afficher 5 caractères
for($x = 0; $x < 5; $x++)
{
    //Couleur au hasard
	$couleur = (mt_rand(0,1)==0) ? $noir : $gris;

	//police au hasard	
	$font = (mt_rand(0,1)==0) ? $font1 : $font2;
	
	//Caractère au hasard
	$v=mt_rand(0,34);
	
	//Le tout dans l'image
	imagettftext($image,$fontsize, mt_rand(0,25), $z, $y, $couleur, $font, $txt[$v]);
	
	//Le code
	$code.=$txt[$v];

	//Espace entre les caractères
	$z+=28;
}

//On affiche des lignes
for($i = 0; $i < 85; $i++)
{
	//Couleur des lignes
	$choix=mt_rand(0,1);
	$couleur = (mt_rand(0,1)==0) ? $noir : $gris;
	
	//Les lignes!
ImageLine($image,mt_rand(0,200),mt_rand(0,200),mt_rand(0,200),mt_rand(0,200),$couleur);
}

//La session qui contient le code
$_SESSION['code'] = $code;

//Le type de la page
header ("Content-type: image/png");
header('Cache-Control: no-store, no-cache, must-revalidate');
imagepng($image);

//On économise les ressources
imageDestroy($image);
?>