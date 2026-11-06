# Retrouver et mettre à jour ce projet sur GitHub

Le dossier local contient le projet. Git conserve son historique. GitHub héberge une copie de cet historique pour que tu puisses la montrer et travailler avec d'autres personnes.

## Ce qui sera publié

Code, documentation, tests, figures et résultats mesurés. Les gros fichiers de données, les bibliothèques installées et les modèles entraînés restent sur ton ordinateur grâce à `.gitignore`. Les scripts permettent de les reconstruire.

Le projet est publié ici : https://github.com/thezanis11/can-sentinel. Le dépôt local est relié à ce dépôt distant. Aucun mot de passe ni jeton ne doit être ajouté aux fichiers du projet ou partagé dans le chat.

## Méthode graphique avec GitHub Desktop

1. Installer GitHub Desktop depuis https://desktop.github.com/ et te connecter à ton compte.
2. Dans GitHub Desktop, choisir **File → Add local repository**, puis le dossier `can-sentinel` de ce projet. Si le dossier n'est pas encore un dépôt, utiliser le lien proposé pour créer un dépôt à cet endroit.
3. Vérifier la liste des fichiers : aucun `.venv`, `data/raw`, `data/processed` ou `models` ne doit apparaître.
4. Si des changements restent à enregistrer, écrire un titre clair puis cliquer sur **Commit to main**.
5. Cliquer sur **Push origin** pour envoyer les nouveaux commits. Ce projet est déjà publié : il n'est pas nécessaire de créer un autre dépôt.
6. Sur GitHub, vérifier le README, l'onglet Actions et le téléchargement des rapports. Ajouter le lien du dépôt dans ton profil et ton CV après l'avoir parcouru.

Les libellés de l'application peuvent évoluer. Pour un autre projet encore local, **Publish repository** permet de créer sa copie sur GitHub ; choisir une visibilité publique pour qu'un recruteur puisse y accéder sans invitation.

Références officielles : [ajouter un dépôt local](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-a-repository-from-your-local-computer-to-github-desktop), [publier un projet existant](https://docs.github.com/en/desktop/adding-and-cloning-repositories/adding-an-existing-project-to-github-using-github-desktop).

## Présenter le dépôt

Description suggérée : `Automotive CAN intrusion detection on real datasets — reproducible training, capture-separated evaluation and failure analysis.`

Sujets suggérés : `automotive-security`, `can-bus`, `intrusion-detection`, `machine-learning`, `python`, `cybersecurity`.

GitHub affiche les fichiers Markdown et les figures. Pour consulter un rapport HTML complet, le télécharger puis l'ouvrir dans un navigateur. Publier un site public est une étape distincte, non nécessaire pour partager le code.

## Après une modification

Vérifier les fichiers modifiés, enregistrer un commit avec une phrase décrivant le changement, puis cliquer sur **Push origin**. Construire un historique de vraies améliorations que tu sais expliquer ; ne pas fabriquer d'activité passée.
