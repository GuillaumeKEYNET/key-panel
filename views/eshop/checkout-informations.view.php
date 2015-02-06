
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			<!-- CHECKOUT ARIANE -->
			<?php include("checkout-ariane.view.php"); 	?>
			<!-- +++++++++++++++++++++++++++++++++++++++ -->
			
			
			
			<!-- NOTIFICATIONS -->
			<?php if( isset( $flash['error'] )) : ?>
				<div class=" notification w100 clear txt12 mb2" style=""><b>Erreur</b>, veuillez verifier vos champs</div>
				<script>jQuery(document).ready(function() {jQuery( ".notification" ).delay(500).hide().slideDown(800);});	</script>
			<?php endif; ?>
			
			<form action="<?= URL ?>/checkout/informations" method="POST" >
			
			<!-- ++++++++++++++++++++++++++++++++++++++++++++++ -->
			<!-- INFOS -->
			<div class="w100 left  ">
				
				<h2 class="w100 left clear mt2 mb2 txt18 txtcenter bgblack txtwhite pa1">
					Vos Informations
				</h2>
				
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Civilité</div>
				<div class="w50 left mt1 txtleft">
					<label><input type="radio" name="client_civilite" value="Madame" class=" ml1 mr1" <?= (@$flash['form_data']['client_civilite']=="Madame") ? 'checked="checked"' : '' ?> />Madame</label>
					<label><input type="radio" name="client_civilite" value="Monsieur" class=" ml3 mr1" <?= (@$flash['form_data']['client_civilite']=="Monsieur") ? 'checked="checked"' : '' ?> />Monsieur</label>
				</div>
				
				<div class="left clear mt2"></div>
				
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Prénom</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_prenom']=='') ? 'error' : ''  ?> " name="client_prenom" value="<?= @$flash['form_data']['client_prenom'] ?>" /></div>
				
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Nom</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_nom']=='') ? 'error' : ''  ?> " name="client_nom" value="<?= @$flash['form_data']['client_nom'] ?>"/></div>
					
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">E-mail</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_email']=='') ? 'error' : ''  ?> " name="client_email" value="<?= @$flash['form_data']['client_email'] ?>"/></div>
					
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Téléphone</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_tel']=='') ? 'error' : ''  ?> " name="client_tel" value="<?= @$flash['form_data']['client_tel'] ?>"/></div>
					
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">adresse</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_adresse']=='') ? 'error' : ''  ?> " name="client_adresse" value="<?= @$flash['form_data']['client_adresse'] ?>"/></div>
					
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">code postal</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_cp']=='') ? 'error' : ''  ?> " name="client_cp" value="<?= @$flash['form_data']['client_cp'] ?>"/></div>
					
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Ville</div>
				<div class="w50  left mt1"><input type="text" class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_ville']=='') ? 'error' : ''  ?> " name="client_ville" value="<?= @$flash['form_data']['client_ville'] ?>"/></div>
					
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Pays</div>
				<div class="w50  left mt1">
					<select class=" w100 <?= ( isset($flash['form_data']) && @$flash['form_data']['client_pays']=='') ? 'error' : ''  ?> " name="client_pays" >
						<option value="ALLEMAGNE(DE)" <?= (@$flash['form_data']['client_pays']=="ALLEMAGNE(DE)") ? 'selected="selected"' : '' ?> >ALLEMAGNE</option>
						<option value="AUTRICHE(AT)"  <?= (@$flash['form_data']['client_pays']=="AUTRICHE(AT)") ? 'selected="selected"' : '' ?> >AUTRICHE</option>
						<option value="BELGIQUE(BE)"  <?= (@$flash['form_data']['client_pays']=="BELGIQUE(BE)") ? 'selected="selected"' : '' ?> >BELGIQUE</option>
						<option value="BULGARIE(BG)"  <?= (@$flash['form_data']['client_pays']=="BULGARIE(BG)") ? 'selected="selected"' : '' ?> >BULGARIE</option>
						<option value="CROATIE(HR)"  <?= (@$flash['form_data']['client_pays']=="CROATIE(HR)") ? 'selected="selected"' : '' ?> >CROATIE</option>
						<option value="DANEMARK(DK)"  <?= (@$flash['form_data']['client_pays']=="DANEMARK(DK)") ? 'selected="selected"' : '' ?> >DANEMARK</option>
						<option value="ESPAGNE(ES)"  <?= (@$flash['form_data']['client_pays']=="ESPAGNE(ES)") ? 'selected="selected"' : '' ?> >ESPAGNE</option>
						<option value="FINLANDE(FI)" <?= (@$flash['form_data']['client_pays']=="FINLANDE(FI)") ? 'selected="selected"' : '' ?> >FINLANDE</option>
						<option value="FRANCE(FR)"  <?= (@$flash['form_data']['client_pays']=="FRANCE(FR)" OR !isset($flash['form_data'])) ? 'selected="selected"' : '' ?> >FRANCE</option>
						<option value="GRÈCE(GR)" <?= (@$flash['form_data']['client_pays']=="GRÈCE(GR)") ? 'selected="selected"' : '' ?> >GRÈCE</option>
						<option value="HONGRIE(HU)" <?= (@$flash['form_data']['client_pays']=="HONGRIE(HU)") ? 'selected="selected"' : '' ?> >HONGRIE</option>
						<option value="IRLANDE(IE)" <?= (@$flash['form_data']['client_pays']=="IRLANDE(IE)") ? 'selected="selected"' : '' ?> >IRLANDE </option>
						<option value="ITALIE(IT)" <?= (@$flash['form_data']['client_pays']=="ITALIE(IT)") ? 'selected="selected"' : '' ?> >ITALIE</option>
						<option value="LETTONIE(LV)" <?= (@$flash['form_data']['client_pays']=="LETTONIE(LV)") ? 'selected="selected"' : '' ?> >LETTONIE</option>
						<option value="LITHUANIE(LT)" <?= (@$flash['form_data']['client_pays']=="LITHUANIE(LT)") ? 'selected="selected"' : '' ?> >LITHUANIE</option>
						<option value="LUXEMBOURG(LU)" <?= (@$flash['form_data']['client_pays']=="LUXEMBOURG(LU)") ? 'selected="selected"' : '' ?> >LUXEMBOURG</option>
						<option value="NORVEGE(NO)" <?= (@$flash['form_data']['client_pays']=="NORVEGE(NO)") ? 'selected="selected"' : '' ?> >NORVEGE</option>
						<option value="PAYS-BAS(NL)" <?= (@$flash['form_data']['client_pays']=="PAYS-BAS(NL)") ? 'selected="selected"' : '' ?> >PAYS-BAS</option>
						<option value="POLOGNE(PL)" <?= (@$flash['form_data']['client_pays']=="POLOGNE(PL)") ? 'selected="selected"' : '' ?> >POLOGNE</option>
						<option value="PORTUGAL(PT)" <?= (@$flash['form_data']['client_pays']=="PORTUGAL(PT)") ? 'selected="selected"' : '' ?> >PORTUGAL</option>
						<option value="REPUBLIQUE TCHEQUE(CZ)" <?= (@$flash['form_data']['client_pays']=="REPUBLIQUE TCHEQUE(CZ)") ? 'selected="selected"' : '' ?> >REPUBLIQUE TCHEQUE</option>
						<option value="ROUMANIE(RO)" <?= (@$flash['form_data']['client_pays']=="ROUMANIE(RO)") ? 'selected="selected"' : '' ?> >ROUMANIE</option>
						<option value="ROYAUME-UNI(GB)" <?= (@$flash['form_data']['client_pays']=="ROYAUME-UNI(GB)") ? 'selected="selected"' : '' ?> >ROYAUME-UNI</option>
						<option value="SAINT MARIN(SM)" <?= (@$flash['form_data']['client_pays']=="SAINT MARIN(SM)") ? 'selected="selected"' : '' ?> >SAINT MARIN</option>
						<option value="SLOVAQUIE(SK)" <?= (@$flash['form_data']['client_pays']=="SLOVAQUIE(SK)") ? 'selected="selected"' : '' ?> >SLOVAQUIE</option>
						<option value="SLOVÉNIE(SI)" <?= (@$flash['form_data']['client_pays']=="SLOVÉNIE(SI)") ? 'selected="selected"' : '' ?> >SLOVÉNIE</option>
						<option value="SUEDE(SE)" <?= (@$flash['form_data']['client_pays']=="SUEDE(SE)") ? 'selected="selected"' : '' ?> >SUEDE</option>
						<option value="SUISSE(CH)" <?= (@$flash['form_data']['client_pays']=="SUISSE(CH)") ? 'selected="selected"' : '' ?> >SUISSE</option>
						<option value="autre" <?= (@$flash['form_data']['client_pays']=="autre") ? 'selected="selected"' : '' ?> >autre (preciser dans infos)</option>
					</select>
				</div>
					
				<div class="w20  left clear txtright mt1 mr1 pt1">informations complémentaire</div>
				<div class="w50  left mt1"><textarea class=" w100  " name="client_infos" ><?= @$flash['form_data']['client_infos'] ?></textarea></div>
				
				<div class="w10  left clear txtright mt3 mr1 pt1">&nbsp;</div>
				<div class="w50 txtleft left mt3">
					<label>
						<input type="checkbox" name="livraison_different" id="livraison_different" class=" ml1 mr1" <?= (@$flash['form_data']['livraison_different']=="on") ? 'checked="checked"' : '' ?> />
						Adresse de livraison différente
					</label>
				</div>
			</div>
			<!-- ++++++++++++++++++++++++++++++++++++++++++++++ -->
			
			<!-- ++++++++++++++++++++++++++++++++++++++++++++++ -->
			<!-- SHIPPING -->
			<div class="w100 left mt3 hide " id="shipping_infos">
				
				<h2 class="w100 left clear mt2 mb2 txt18 txtcenter bgdarkgrey txtwhite pa1">
					Informations de livraison
				</h2>
				
				
				<div class="w20  left clear txtright txtleftm mt1 mr1 ptv">Civilité</div>
				<div class="w50 left mt1 txtleft">
					<label><input type="radio" name="livraison_civilite" value="Madame" class=" ml1 mr1"  <?= (@$flash['form_data']['livraison_civilite']=="Madame") ? 'checked="checked"' : '' ?>  />Madame</label>
					<label><input type="radio" name="livraison_civilite" value="Monsieur" class=" ml3 mr1"  <?= (@$flash['form_data']['livraison_civilite']=="Madame") ? 'checked="checked"' : '' ?>  />Monsieur</label>
				</div>
				
				<div class="left clear mt2"></div>
				
				<div class="w20 left clear txtright mt1 mr1 ptv">Prénom</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_prenom" value="<?= @$flash['form_data']['livraison_prenom'] ?>" /></div>
				
				<div class="w20 left clear txtright mt1 mr1 ptv">Nom</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_nom" value="<?= @$flash['form_data']['livraison_nom'] ?>" /></div>
					
				<div class="w20 left clear txtright mt1 mr1 ptv">E-mail</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_email" value="<?= @$flash['form_data']['livraison_email'] ?>" /></div>
					
				<div class="w20 left clear txtright mt1 mr1 ptv">Téléphone</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_tel" value="<?= @$flash['form_data']['livraison_tel'] ?>" /></div>
					
				<div class="w20 left clear txtright mt1 mr1 ptv">adresse</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_adresse" value="<?= @$flash['form_data']['livraison_adresse'] ?>" /></div>
					
				<div class="w20 left clear txtright mt1 mr1 ptv">code postal</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_cp" value="<?= @$flash['form_data']['livraison_cp'] ?>" /></div>
					
				<div class="w20 left clear txtright mt1 mr1 ptv">Ville</div>
				<div class="w50  left mt1"><input type="text" class=" w100  " name="livraison_ville" value="<?= @$flash['form_data']['livraison_ville'] ?>" /></div>
					
				<div class="w20 left clear txtright mt1 mr1 ptv">Pays</div>
				<div class="w50  left mt1">
					<select class=" w100  " name="livraison_pays" >
						<option value="ALLEMAGNE(DE)" <?= (@$flash['form_data']['livraison_pays']=="ALLEMAGNE(DE)") ? 'selected="selected"' : '' ?> >ALLEMAGNE</option>
						<option value="AUTRICHE(AT)"  <?= (@$flash['form_data']['livraison_pays']=="AUTRICHE(AT)") ? 'selected="selected"' : '' ?> >AUTRICHE</option>
						<option value="BELGIQUE(BE)"  <?= (@$flash['form_data']['livraison_pays']=="BELGIQUE(BE)") ? 'selected="selected"' : '' ?> >BELGIQUE</option>
						<option value="BULGARIE(BG)"  <?= (@$flash['form_data']['livraison_pays']=="BULGARIE(BG)") ? 'selected="selected"' : '' ?> >BULGARIE</option>
						<option value="CROATIE(HR)"  <?= (@$flash['form_data']['livraison_pays']=="CROATIE(HR)") ? 'selected="selected"' : '' ?> >CROATIE</option>
						<option value="DANEMARK(DK)"  <?= (@$flash['form_data']['livraison_pays']=="DANEMARK(DK)") ? 'selected="selected"' : '' ?> >DANEMARK</option>
						<option value="ESPAGNE(ES)"  <?= (@$flash['form_data']['livraison_pays']=="ESPAGNE(ES)") ? 'selected="selected"' : '' ?> >ESPAGNE</option>
						<option value="FINLANDE(FI)" <?= (@$flash['form_data']['livraison_pays']=="FINLANDE(FI)") ? 'selected="selected"' : '' ?> >FINLANDE</option>
						<option value="FRANCE(FR)"  <?= (@$flash['form_data']['livraison_pays']=="FRANCE(FR)" OR !isset($flash['form_data'])) ? 'selected="selected"' : '' ?> >FRANCE</option>
						<option value="GRÈCE(GR)" <?= (@$flash['form_data']['livraison_pays']=="GRÈCE(GR)") ? 'selected="selected"' : '' ?> >GRÈCE</option>
						<option value="HONGRIE(HU)" <?= (@$flash['form_data']['livraison_pays']=="HONGRIE(HU)") ? 'selected="selected"' : '' ?> >HONGRIE</option>
						<option value="IRLANDE(IE)" <?= (@$flash['form_data']['livraison_pays']=="IRLANDE(IE)") ? 'selected="selected"' : '' ?> >IRLANDE </option>
						<option value="ITALIE(IT)" <?= (@$flash['form_data']['livraison_pays']=="ITALIE(IT)") ? 'selected="selected"' : '' ?> >ITALIE</option>
						<option value="LETTONIE(LV)" <?= (@$flash['form_data']['livraison_pays']=="LETTONIE(LV)") ? 'selected="selected"' : '' ?> >LETTONIE</option>
						<option value="LITHUANIE(LT)" <?= (@$flash['form_data']['livraison_pays']=="LITHUANIE(LT)") ? 'selected="selected"' : '' ?> >LITHUANIE</option>
						<option value="LUXEMBOURG(LU)" <?= (@$flash['form_data']['livraison_pays']=="LUXEMBOURG(LU)") ? 'selected="selected"' : '' ?> >LUXEMBOURG</option>
						<option value="NORVEGE(NO)" <?= (@$flash['form_data']['livraison_pays']=="NORVEGE(NO)") ? 'selected="selected"' : '' ?> >NORVEGE</option>
						<option value="PAYS-BAS(NL)" <?= (@$flash['form_data']['livraison_pays']=="PAYS-BAS(NL)") ? 'selected="selected"' : '' ?> >PAYS-BAS</option>
						<option value="POLOGNE(PL)" <?= (@$flash['form_data']['livraison_pays']=="POLOGNE(PL)") ? 'selected="selected"' : '' ?> >POLOGNE</option>
						<option value="PORTUGAL(PT)" <?= (@$flash['form_data']['livraison_pays']=="PORTUGAL(PT)") ? 'selected="selected"' : '' ?> >PORTUGAL</option>
						<option value="REPUBLIQUE TCHEQUE(CZ)" <?= (@$flash['form_data']['livraison_pays']=="REPUBLIQUE TCHEQUE(CZ)") ? 'selected="selected"' : '' ?> >REPUBLIQUE TCHEQUE</option>
						<option value="ROUMANIE(RO)" <?= (@$flash['form_data']['livraison_pays']=="ROUMANIE(RO)") ? 'selected="selected"' : '' ?> >ROUMANIE</option>
						<option value="ROYAUME-UNI(GB)" <?= (@$flash['form_data']['livraison_pays']=="ROYAUME-UNI(GB)") ? 'selected="selected"' : '' ?> >ROYAUME-UNI</option>
						<option value="SAINT MARIN(SM)" <?= (@$flash['form_data']['livraison_pays']=="SAINT MARIN(SM)") ? 'selected="selected"' : '' ?> >SAINT MARIN</option>
						<option value="SLOVAQUIE(SK)" <?= (@$flash['form_data']['livraison_pays']=="SLOVAQUIE(SK)") ? 'selected="selected"' : '' ?> >SLOVAQUIE</option>
						<option value="SLOVÉNIE(SI)" <?= (@$flash['form_data']['livraison_pays']=="SLOVÉNIE(SI)") ? 'selected="selected"' : '' ?> >SLOVÉNIE</option>
						<option value="SUEDE(SE)" <?= (@$flash['form_data']['livraison_pays']=="SUEDE(SE)") ? 'selected="selected"' : '' ?> >SUEDE</option>
						<option value="SUISSE(CH)" <?= (@$flash['form_data']['livraison_pays']=="SUISSE(CH)") ? 'selected="selected"' : '' ?> >SUISSE</option>
						<option value="autre" <?= (@$flash['form_data']['livraison_pays']=="autre") ? 'selected="selected"' : '' ?> >autre (preciser dans infos)</option>
					</select>
				</div>
					
				<div class="w20 left clear txtright mt1 mr1 pt1">informations complémentaire</div>
				<div class="w50  left mt1"><textarea class=" w100 " name="livraison_infos" ><?= @$flash['form_data']['livraison_infos'] ?></textarea></div>
			
			
			</div>
			<!-- ++++++++++++++++++++++++++++++++++++++++++++++ -->
			
			
			<div class="left clear mt1"></div>
			
			<div class="mt3  left clear  ">
				<a href="<?= URL ?>/eshop/cart" class="border0 txtwhite txt12 bgdarkgrey txtcenter pr3 pl3 ptv pbv">Retour</a>
			</div>
					
			<div class="mt3 mr1 right  txtdin txt24 txtwhite  ">
				<input type="submit" class="border0 txtwhite txt20 bgdarkblue txtcenter ptv pbv pr3 pl3" value="Poursuivre" />
			</div>
			
			
			</form>
			
			
			<!-- .................................... -->
			<!-- SPACE -->
			<div class="left clear mt2"></div>
			<!-- .................................... -->
			
			
			<script>
				
				$(document).ready( function(){
					  
					function check_livraison_different(){
						if ($("#livraison_different").is(":checked")) 
							$('#shipping_infos').slideDown();
						else
							$('#shipping_infos').slideUp();
					}
					$("#livraison_different").click(function(){ check_livraison_different(); });
					
					check_livraison_different();
					
					
				});
			
			</script>
			 
		