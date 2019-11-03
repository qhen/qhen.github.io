function codeContenu(id) {
	var contenu=document.getElementById(id).value;
	return encodeURIComponent(contenu);
}

function createXHR() {
	var resultat=null;
	try {
		// Test pour les navigateurs : Mozilla, Opera...
		resultat= new XMLHttpRequest();
	}
	catch (Error) {
		try {
			// Test pour les navigateurs Internet Explorer > 5.0
			resultat= new ActiveXObject("Msxml2.XMLHTTP");
		} catch (Error) {
			try {
				// Test pour le navigateur Internet Explorer 5.0
				resultat= new ActiveXObject("Microsoft.XMLHTTP");
			} catch (Error) {
				resultat= null;
			}
		}
	}
	return resultat;
}

function supprimerContenu(element) {
	if (element != null) {
		while(element.firstChild)
		element.removeChild(element.firstChild);
	}
}

function remplacerContenu(id, texte) {
	var element = document.getElementById(id);
	if (element != null) {
		supprimerContenu(element);
		var nouveauContenu = document.createTextNode(texte);
		element.appendChild(nouveauContenu);
	}
}