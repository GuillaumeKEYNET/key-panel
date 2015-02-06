<html>

<h3 style='font-size: 16px; font-family: times, serif; color: #000; '>
	<img src="<?= URL ?>/assets/images/motmotbijoux-logo.png" alt="MOTMOTBIJOUX" />
</h3>
<br />
Votre commande a bien été validée.<br />Merci de votre confiance.
<br />
<br />
############################################################<br />
<b>COMMANDE <?= $order['reference'] ?></b><br />
############################################################<br />
<br />
-------------------------------------------<br />
<b>DETAIL DE LA COMMANDE :</b> <br>
-------------------------------------------<br />
<?= $order['products'] ?> <br />
Total panier : <?= $order['total_cart'] ?> €<br />
Livraison <?= $order['carrier']['name'] ?> : <?= $order['total_carrier'] ?> €<br />
<b>TOTAL : <?= $order['total'] ?> € </b><br /><br />
<i>Paiement par <?= $order['payment']['name'] ?></i><br />
############################################################<br />

<br />
-------------------------------------------<br />
FACTURATION<br />
-------------------------------------------<br />
<b>civilite :</b> <?= $order['address_facturation']['civilite'] ?> <br />
<b>nom :</b> <?= $order['address_facturation']['nom'] ?> <br />
<b>prenom :</b> <?= $order['address_facturation']['prenom'] ?> <br />
<b>email :</b> <?= $order['address_facturation']['email'] ?> <br />
<b>telephone :</b> <?= $order['address_facturation']['tel'] ?> <br />
<b>adresse :</b> <?= $order['address_facturation']['adresse'] ?> <br />
<b>code postal :</b> <?= $order['address_facturation']['cp'] ?> <br />
<b>ville :</b> <?= $order['address_facturation']['ville'] ?> <br />
<b>pays :</b> <?= $order['address_facturation']['pays'] ?> <br />
<b>infos :</b><br /> <?= nl2br($order['address_facturation']['infos']) ?> <br /><br />
-------------------------------------------<br />
LIVRAISON<br />
-------------------------------------------<br />
<b>civilite :</b> <?= $order['address_livraison']['civilite'] ?> <br />
<b>nom :</b> <?= $order['address_livraison']['nom'] ?> <br />
<b>prenom :</b> <?= $order['address_livraison']['prenom'] ?> <br />
<b>email :</b> <?= $order['address_livraison']['email'] ?> <br />
<b>telephone :</b> <?= $order['address_livraison']['tel'] ?> <br />
<b>adresse :</b> <?= $order['address_livraison']['adresse'] ?> <br />
<b>code postal :</b> <?= $order['address_livraison']['cp'] ?> <br />
<b>ville :</b> <?= $order['address_livraison']['ville'] ?> <br />
<b>pays :</b> <?= $order['address_livraison']['pays'] ?> <br />
<b>infos :</b><br /> <?= nl2br($order['address_livraison']['infos']) ?> <br /><br />


</html>
