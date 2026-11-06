# Comprendre et montrer CAN Sentinel

## Démonstration de cinq minutes

1. Ouvrir `reports/index.html`. Expliquer : « J'étudie la détection d'intrusions dans les messages échangés par les calculateurs d'un véhicule. »
2. Montrer les trois modèles et le compromis entre attaques détectées et fausses alertes.
3. Afficher le détail par famille et une capture où le modèle se trompe. Une erreur expliquée vaut mieux qu'un chiffre isolé.
4. Ouvrir le second rapport : comparer véhicule connu et inconnu. Expliquer que le sens d'un identifiant CAN peut changer d'un véhicule à l'autre.
5. Montrer la commande de reproduction, les tests et le manifeste. Distinguer ce qui a été mesuré de ce qui reste une piste.

## Les notions à comprendre

**CAN** est un réseau embarqué. Plusieurs calculateurs diffusent des messages avec un identifiant et quelques octets de données. Un identifiant n'est pas une adresse IP ni une identité authentifiée d'émetteur.

**IDS** signifie système de détection d'intrusions. Il signale une observation suspecte ; une alerte ne prouve pas automatiquement une attaque, et détecter ne signifie pas bloquer.

**Fenêtre de 500 ms** : le programme regroupe les messages d'une demi-seconde, puis calcule des caractéristiques. Un message injecté peut rendre la fenêtre entière positive. Les scores ne sont donc pas des taux de détection par message.

**Précision** : parmi les fenêtres signalées, quelle proportion correspond aux labels d'attaque ? **Rappel** : parmi les fenêtres d'attaque, quelle proportion est signalée ? **F1** combine précision et rappel. Le **taux de faux positifs** mesure la part des fenêtres normales signalées à tort. Aucun de ces chiffres ne suffit seul.

**Entraînement / validation / test** : apprendre les modèles / choisir les seuils / mesurer les performances. Avec des séries temporelles, mélanger aléatoirement des messages voisins peut donner une estimation trompeuse. Ici, les captures sont séparées et les variantes dérivées restent ensemble.

## Questions possibles en entretien

- Pourquoi trois méthodes ? Pour vérifier si la complexité de l'apprentissage apporte quelque chose face à un profil statistique explicable.
- Pourquoi pas immédiatement un réseau de neurones ? Il faut d'abord des références simples, une évaluation solide et une raison mesurée d'ajouter de la complexité.
- Pourquoi les modèles non supervisés peuvent-ils échouer ? Une activité normale inhabituelle peut être plus atypique qu'une attaque discrète.
- Pourquoi le seuil change-t-il tout ? Un score ordonne les observations ; le seuil décide quelles observations produisent une alerte et fixe le compromis pratique.
- Est-ce un projet de conduite autonome ? C'est un projet de sécurité des communications automobiles, pertinent pour les véhicules connectés et autonomes, sans fonction de conduite.
- Qu'as-tu fait toi-même ? Décrire précisément ce que tu as compris, revu, modifié et expérimenté, ainsi que l'assistance utilisée.

## Trois contributions personnelles utiles

1. Ajouter un regroupement d'alertes consécutives et comparer fenêtres fausses positives et incidents d'alerte.
2. Étudier 100 ms / 500 ms / 1 s avec un protocole fixé à l'avance. Publier aussi les résultats moins bons.
3. Ajouter une nouvelle capture indépendante ou un protocole complet CTT, puis figer le code avant de consulter ses résultats.

Ces contributions sont proposées pour poursuivre l'apprentissage. Elles ne sont pas revendiquées comme déjà réalisées.

## Formulation CV après appropriation du projet

« CAN Sentinel — Développement assisté et évaluation d'un prototype Python de détection d'intrusions automobiles sur ROAD et un sous-ensemble can-train-and-test ; traitement de captures CAN, comparaison de trois modèles, évaluation par captures et analyse des fausses alertes. »

Ajouter un score seulement en précisant le dataset, le protocole et le taux de fausses alertes. Ne pas présenter le projet comme un système déployé en véhicule ni comme une protection validée industriellement.
