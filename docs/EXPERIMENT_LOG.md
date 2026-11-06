# Journal expérimental et limites

## 1. Acquisition

ROAD a été téléchargé depuis le dépôt officiel Zenodo, record 10462796. Taille attendue : 556 718 276 octets ; MD5 attendu : cab184cfc2fe12c0834bc46188c0f330. L'archive a été vérifiée avant traitement. Lecture directe dans le ZIP pour éviter une copie décompressée de plusieurs Go. Aucun fichier de référence du projet ChatGPT n'est modifié.

## 2. Premier réglage : faible taux de fausses alertes

Les trois modèles ont d'abord été comparés avec un seuil limitant à 1 % les fausses alertes en validation. Les résultats de test ont été consultés. Ils sont conservés dans `reports/initial_strict_metrics.csv` et `reports/initial_strict_experiment.json`.

Ce réglage a produit un rappel très faible sur les attaques de test. Il a aussi révélé que la contrainte empirique sur la validation ne garantit pas le même comportement dans de nouvelles conditions normales.

## 3. Deux points de fonctionnement

Le benchmark affiche désormais le réglage strict et un réglage équilibré maximisant le F1 en validation. Les modèles et caractéristiques restent les mêmes. Les seuils équilibrés des trois modèles utilisent les labels de validation ; il ne faut donc pas présenter ces seuils comme entièrement non supervisés.

Le modèle retenu est celui qui obtient le meilleur F1 de validation. Les métriques du test n'entrent pas dans cette sélection automatique. Cependant, le choix de présenter un second point de fonctionnement a été fait après observation des premiers résultats : **l'étude ROAD est exploratoire et ne constitue pas un test final aveugle**. Un futur audit doit figer le code avant l'accès à de nouvelles captures indépendantes.

## 4. Second dataset

Le dépôt officiel can-train-and-test contient quatre protocoles et quatre véhicules. Pour maîtriser le volume tout en couvrant les scénarios, on fixe avant évaluation :

- `set_01` uniquement ;
- tous les fichiers de `train_01` ;
- répétitions `-1` pour apprendre, `-2` pour valider ;
- première répétition disponible, par famille et dossier de test, dans l'ordre lexicographique ;
- quatre dossiers de test officiels : véhicule / attaque connus ou inconnus.

Les identifiants, horodatages et octets sont traités avec la même famille de caractéristiques que ROAD. Les modèles sont réentraînés localement. Un autre essai applique le modèle ROAD figé sans adaptation. Les deux expériences répondent à des questions différentes.

Les premiers contrôles CTT ont révélé de petites inversions d'horodatage dans certaines captures d'injection (par exemple, 50 pas négatifs d'au plus environ 134 microsecondes dans force-neutral-3 sur véhicule connu). On applique un tri stable global par capture avant l'extraction des fenêtres et on compte les inversions. Ce traitement ne modifie pas les fichiers originaux et ne consulte pas les résultats des modèles. Le tri nécessite de lire une capture à la fois en mémoire ; le reste de l'extraction utilise des blocs.

Téléchargement par plages HTTP depuis l'archive officielle : contrôle CRC32 des membres ZIP et SHA256 local. Le MD5 attendu de l'archive est enregistré, mais n'est pas revendiqué comme vérifié pour ce téléchargement partiel. La sélection est exportée dans le manifeste. Les doublons exacts entre lots sont rejetés.

## Limites à citer

- ROAD concerne un seul véhicule anonymisé, dont les identifiants ne sont pas des signaux physiques universels.
- Les variantes masquerade dérivent des captures fabrication : elles ne sont pas des expériences indépendantes.
- Les labels ROAD reconstruits sont approximatifs ; les labels CTT sont fournis par les auteurs.
- La fenêtre positive peut contenir une très faible proportion de messages malveillants.
- Les quatre captures accelerator ne fournissent pas de vérité terrain de messages injectés et sont exclues des métriques binaires.
- Les périodes sans trame ne produisent aucune fenêtre ; le système ne détecte pas l'arrêt total d'un réseau.
- Les ID FFF de ROAD sont des placeholders supprimés, pas des ID CAN physiques exploités par le modèle.
- Les payloads CTT courts sont complétés par des zéros et leur longueur initiale n'est pas une caractéristique : c'est une simplification.
- Les captures d'un même véhicule ne suffisent pas pour prouver une généralisation industrielle.
- Le code a été produit avec une assistance IA ; une revue humaine et des expériences supplémentaires sont nécessaires avant tout usage opérationnel.
