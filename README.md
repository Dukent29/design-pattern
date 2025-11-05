# Security Patterns Demo

Petit projet Flask qui illustre plusieurs patrons de sécurité (authentification, RBAC, audit logging, validation d’entrées) dans une application web minimale.

## Réponses à l’exercice 6

1. **Méthode de hachage**  
   Les mots de passe sont hachés via `werkzeug.security.generate_password_hash` configuré avec l’algorithme `pbkdf2:sha256` et un sel aléatoire de 16 octets. PBKDF2 ajoute une étape de dérivation lente et salée qui complique fortement une attaque par force brute ou rainbow table.

2. **Renouvellement de session**  
   Chaque session expirerait au bout de 30 minutes (`SESSION_DURATION`). À chaque requête authentifiée, `AuthenticationEnforcer.check_authentication` prolonge la date d’expiration (sliding expiration) tant que l’utilisateur reste actif.

3. **Après 5 échecs de connexion**  
   L’application journalise chaque échec (`audit_event("login_failed", …)`) mais ne déclenche aucune mise en quarantaine automatique. Le verrouillage après N tentatives fait partie des évolutions recommandées (par exemple via un compteur en mémoire ou en base avec délai de refroidissement).

## Structure du projet

```
security_app/
├─ app.py                   # Point d’entrée Flask
├─ security/                # Modules métier
│  ├─ authentication.py     # Authentification + session management (MySQL)
│  ├─ authorization.py      # Décorateurs RBAC
│  ├─ validation.py         # Validation / détection basique SQLi
│  └─ audit.py              # Journalisation structurée JSON
├─ templates/               # HTML (login, dashboard, admin, erreurs)
└─ security.log             # Log d’audit (exclure en prod)
```

## Installation rapide

```bash
python -m venv security_patterns_env
source security_patterns_env/bin/activate  # Windows: security_patterns_env\Scripts\activate
pip install -r requirements.txt            # sinon: pip install flask sqlalchemy pymysql python-dotenv
python app.py
```

Par défaut l’application expose `http://127.0.0.1:5000`.  
Comptes de démonstration : `admin / Admin#1234`, `alice / User#1234`, etc.

### Base de données MySQL

- Démarrez MySQL (ex. via XAMPP) et créez la base :
  ```sql
  CREATE DATABASE IF NOT EXISTS `security-patterns` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
  ```
- L’application se connecte par défaut avec l’utilisateur `root` sans mot de passe sur `localhost:3306`.  
  Si nécessaire, ajustez la chaîne dans `.env` :
  ```
  DATABASE_URL=mysql+pymysql://root:@localhost:3306/security-patterns
  ```
- Au premier lancement, les comptes de démonstration sont insérés dans la table `users`.

### Création des utilisateurs

Seuls les administrateurs peuvent créer de nouveaux comptes :

- Depuis le tableau de bord (`/dashboard`), un bouton « Créer un utilisateur » apparaît uniquement pour les profils ayant le rôle `admin`. Il redirige vers `/admin`, où un formulaire permet de saisir `nom d’utilisateur`, `mot de passe` et `rôle`.  
- L’API `POST /api/users` permet la même opération en JSON, mais nécessite d’être authentifié en tant qu’admin (session/cookie). Exemple :
  ```json
  {
    "username": "nouvelutilisateur",
    "password": "Motdepasse#123",
    "role": "viewer"
  }
  ```

Dans les deux cas, le mot de passe est immédiatement haché via PBKDF2, la ligne est insérée en base MySQL, et un événement d’audit (`user_created`, `user_creation_success` ou `user_creation_failed`) est ajouté dans `security.log`.

### Comptes disponibles

| Nom d’utilisateur | Mot de passe       | Rôle        |
|-------------------|--------------------|-------------|
| admin             | Admin#1234         | admin       |
| alice             | User#1234          | editor      |
| bob               | AnalystPass123!    | viewer      |
| carol             | ViewerPass123!     | viewer      |
| charlie           | User#1234          | viewer      |

## Choix techniques

- **Langage** : Python, parce qu’il propose une syntaxe lisible et un écosystème riche (Flask, Werkzeug) pour prototyper rapidement des concepts de sécurité. C’était aussi l’occasion de se familiariser avec une stack différente.
- **Front-end** : HTML/CSS très simples afin de se concentrer sur les patterns sécurité. Pas de framework JS, juste un peu de style utilitaire pour gagner du temps tout en gardant une interface claire.
- **Persistance** : MySQL via SQLAlchemy, pour que les utilisateurs créés par un administrateur persistent au-delà du cycle de vie du processus.
- **Audit** : tous les événements sensibles (tentatives de connexion, refus d’accès, création d’utilisateur) écrivent une ligne JSON dans `security.log` pour faciliter l’analyse.

## Pistes d’amélioration

- Comptage des échecs de connexion et blocage temporaire / captchas.
- Journalisation vers un SIEM ou un backend centralisé.
- Gestion d’utilisateurs persistants (SQLite, MySQL, MongoDB…).
- Tests automatisés (unitaires + tests sécurité).
- Renforcement du front : templating étendu, meilleure UX.

## Licence

Libre de réutiliser/adapter ce code pour des exercices ou démos pédagogiques.
