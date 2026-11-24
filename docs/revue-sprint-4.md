# Revue du Sprint 4 - Frontend, authentification et Kibana

Période : 23/11/2026 au 27/11/2026. Objectif : terminer le socle obligatoire (upload, recherche, visualisation, accès sécurisé).

## État des user stories

| Story | Contenu | État |
|---|---|---|
| US01 | Authentification et rôles (lecteur, analyste, admin), sessions Redis | Terminée |
| US02 | Upload par glisser-déposer, prévisualisation, barre de progression | Terminée |
| US03 | Liste des fichiers avec statut d'ingestion (suivi automatique) | Terminée |
| US04 | Recherche par texte et filtres, 50 résultats par page, détail d'un événement, historique | Terminée |
| US05 | Tableau de bord (4 indicateurs, 4 graphiques, choix de la période) | Terminée |
| US06 | Dashboards Kibana (3 visualisations Lens + carte) intégrés dans l'application | À valider dans Kibana |
| US12 | Export CSV des résultats avec les filtres actifs | Terminée |

## Scénario de démonstration (10 minutes)

1. Ouvrir `http://localhost:8000/` sans être connecté : redirection vers la page de connexion.
2. Se connecter en **lecteur** : tableau de bord et recherche accessibles, `/upload` affiche « 403 Accès refusé », aucun lien « Import de logs ».
3. Se déconnecter, se connecter en **analyste** : importer un fichier CSV par glisser-déposer, voir la progression, la prévisualisation et le passage du statut à « Ingéré ».
4. Page **Recherche** : filtrer par gravité `critical`, trier, changer de page, cliquer sur une ligne pour le détail, exporter en CSV, relancer une recherche depuis l'historique.
5. Page **Tableau de bord** : changer la période (24 h, 7 jours, 30 jours).
6. Page **Kibana** : tableau de bord intégré (courbe des échecs, top 10 des IP, top 10 des pays, carte).
7. Se connecter en **admin** : la liste noire d'IP est accessible (`/api/v1/blacklist`), l'historique montre les recherches de tous les utilisateurs.

## Vérification responsive (à faire dans le navigateur)

Ouvrir les outils de développement (F12), activer l'affichage mobile (Ctrl + Maj + M), tester les largeurs 375 px, 768 px et 1280 px :

- [ ] Navbar : se replie en menu à 375 px, le bouton fonctionne.
- [ ] Tableau de bord : indicateurs sur 2 colonnes (mobile) puis 4 (large), graphiques lisibles.
- [ ] Import : zone de dépôt utilisable, tableau des fichiers défile horizontalement sans casser la page.
- [ ] Recherche : filtres empilés, tableau défilant, fenêtre de détail lisible.
- [ ] Connexion : formulaire centré, pas de débordement.
- [ ] Kibana : cadre à pleine largeur.

## Qualité

- 75 tests automatisés (pytest), flake8 sans erreur, couverture mesurée à 68 % (objectif du module K : plus de 70 %).
- Revue de sécurité du sprint : contrôle d'accès par défaut (tout est protégé sauf `/health`, `/login` et `/auth/*`), aucune redirection externe après connexion, échappement de toutes les données affichées, neutralisation des formules dans l'export CSV, en-têtes `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` et `Cache-Control: no-store` sur les pages.
- Défauts corrigés pendant la revue : historique de recherche incomplet (réponses en cache non enregistrées) et visible par tous (désormais par utilisateur, l'admin voit tout, sans doublon sur une minute).

## Limites connues et suite

- La carte Kibana se crée à la main dans l'application Maps puis s'ajoute au tableau de bord.
- Le chiffre « Événements critiques » compte les événements de gravité critique ; les vraies alertes arrivent au Sprint 5 (module G).
- Sécurité Elastic désactivée en développement ; le cookie de session passera en `Secure` derrière HTTPS (`SESSION_COOKIE_SECURE=1`).
- Pagination limitée à 10 000 résultats (limite d'Elasticsearch) ; l'export est limité à 10 000 lignes.
- Sprint 5 : alerting (US07, US08, US09, US10, US11, US13) et CI/CD (US15).
