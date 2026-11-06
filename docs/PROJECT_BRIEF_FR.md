# CAN Sentinel — dossier de projet

## Objectif
Construire et évaluer un système de détection d'intrusions dans les communications CAN d'un véhicule, à partir de captures publiques réelles. Livrer du code reproductible, des modèles entraînés, un rapport consultable et une explication des limites.

Ce projet concerne la cybersécurité des réseaux embarqués automobiles. Il ne constitue pas un système de conduite autonome, même si cette sécurité est une composante des véhicules autonomes.

## Sources retenues
- ROAD, Oak Ridge National Laboratory : https://zenodo.org/records/10462796 — archive de 556 718 276 octets ; CC BY 4.0 selon les métadonnées Zenodo. Source principale des expériences.
- can-train-and-test, Brooke Lampe et collaborateurs : https://doi.org/10.11583/DTU.24805533 — archive de 1 507 455 719 octets ; CC BY 4.0 selon l'API Figshare. Évaluation complémentaire sur un sous-ensemble de 32 fichiers du protocole set_01 : toutes les familles, quatre scénarios, deux véhicules. Téléchargement partiel documenté, résultats distincts du benchmark ROAD.
- HCRL Car-Hacking : https://sites.google.com/hksecurity.net/hcrl/Datasets/CAN-intrusion-dataset — accès officiel sur questionnaire et lien envoyé par e-mail ; non retenu comme dépendance automatique.

Le téléchargement d'une archive ne signifie pas qu'elle a été évaluée. Seuls les résultats accompagnés d'un manifeste d'expérience sont présentés comme mesurés.

## Ce qui rend l'évaluation crédible
- Séparer les captures d'entraînement, de validation et de test, sans mélange aléatoire de messages voisins.
- Garder ensemble les variantes issues d'une même capture, notamment fabrication et masquerade.
- Apprendre les transformations et les seuils uniquement sur l'entraînement / la validation.
- Ne jamais donner au modèle les noms de fichiers, horodatages absolus, labels ou métadonnées d'injection.
- Publier précision, rappel, F1, PR-AUC, taux de fausses alertes et résultats par famille d'attaque ; l'accuracy seule est insuffisante.
- Identifier les labels reconstruits à partir des métadonnées comme des approximations.

## Livrables
1. Téléchargement avec contrôle d'intégrité et traçabilité.
2. Lecture et validation des captures, extraction de caractéristiques sur fenêtres temporelles.
3. Détecteur statistique explicable, Isolation Forest et modèle supervisé, avec protocoles documentés.
4. Rapport de benchmark et figures exportables.
5. Commande d'analyse hors ligne d'une capture compatible.
6. Tests, vérification automatique GitHub, documentation d'installation et guide d'entretien.

## Suite du portfolio
Après avoir compris et personnalisé ce projet : Secure Convoy (simulation de véhicules et messages altérés), puis Network Watch (analyse de journaux réseau). La priorité est de maîtriser un projet abouti avant d'en afficher plusieurs sur un CV.
