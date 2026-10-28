# Meta ShieldFin

Meta ShieldFin est une console SOC FastAPI destinée à superviser des transactions,
à journaliser les décisions des opérateurs et à intégrer des fournisseurs externes
configurables. Les intégrations ne simulent pas leur succès : une opération échoue
explicitement si ses identifiants, ses destinations ou son service externe manquent.

Ce dépôt est un socle applicatif exploitable, pas une certification bancaire ni une
garantie de conformité. Avant tout traitement réel, faites auditer la sécurité, les
modèles, la conservation des données et les obligations réglementaires dans votre
juridiction. N'utilisez pas les données d'exemple en production.

## Fonctions opérationnelles

- API FastAPI et interface SOC couvrant transactions, audit, défis, AML, recherche et
  règles apprises.
- Authentification opérateur par mot de passe Argon2 et session signée, révocable,
  stockée dans un cookie `HttpOnly`; rôles `ANALYST` et `SENIOR`.
- Initialisation du premier opérateur senior avec `ADMIN_EMAIL` et
  `ADMIN_PASSWORD`. Les créations, désactivations et actions sensibles sont protégées
  par rôle. Les connexions sont limitées par adresse IP.
- Persistance SQLite pour le développement et PostgreSQL en déploiement.
- OTP aléatoire, haché avec `OTP_PEPPER`, limité dans le temps et en nombre d'essais.
  Les réponses client de défi sont publiques à l'endpoint dédié; les autres API
  nécessitent une session opérateur ou la clé de service d'ingestion.
- Envoi SMS Twilio, Telegram et Firebase Cloud Messaging (FCM), si le fournisseur,
  les secrets et la destination chiffrée ont été configurés.
- Chiffrement Fernet des destinations de notification avec `CONTACTS_ENCRYPTION_KEY`.
- Détection locale déterministe, Isolation Forest entraîné uniquement après collecte
  de transactions approuvées, et classifieur supervisé à partir des annotations
  humaines. Un seuil issu de validation croisée reste inactif jusqu'à l'approbation
  explicite d'un opérateur senior.
- Synchronisation fédérée HTTPS signée HMAC, protégée contre les rejeux et limitée
  aux agrégats dépassant une cohorte minimale. Les recommandations reçues sont
  soumises à approbation humaine.
- Export PDF de dossier à vérifier par un analyste; il ne constitue pas un dépôt
  réglementaire.

La fédération HMAC n'est pas une agrégation sécurisée cryptographique ni une garantie
de confidentialité différentielle. Les métriques d'évaluation de profils synthétiques
ne prédisent pas la performance en production. L'Isolation Forest et le classifieur
doivent être évalués sur des données représentatives, autorisées et contrôlées avant
de contribuer à une décision financière.

## Développement local

Prérequis : Python 3.11 ou supérieur.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
cp .env.example .env
```

Générez des secrets propres à cette installation et renseignez-les dans `.env` :

```bash
openssl rand -hex 32   # AUTH_SECRET_KEY
openssl rand -hex 32   # OTP_PEPPER
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Définissez également `ADMIN_EMAIL` et un `ADMIN_PASSWORD` unique d'au moins
16 caractères. Gardez `.env` hors du contrôle de version et protégez-le avec des
permissions restreintes. Puis démarrez l'application :

```bash
uvicorn backend.main:app --reload
```

Ouvrir http://127.0.0.1:8000. La documentation interactive est disponible sur
http://127.0.0.1:8000/docs. En développement, SQLite est créé à l'emplacement de
`DATABASE_PATH` et les transactions d'exemple peuvent être insérées si
`SEED_DEMO_DATA=true` (valeur par défaut pour le mode local).

Les tests API :

```bash
python -m unittest discover -s tests -v
```

## Déploiement Docker avec PostgreSQL

1. Copiez `.env.example` en `.env`; générez les secrets comme ci-dessus et remplacez
   tous les mots de passe et valeurs d'exemple. `POSTGRES_PASSWORD` doit être URL-safe
   (lettres et chiffres) car il est incorporé à `DATABASE_URL`.
2. Définissez un `ADMIN_EMAIL`, un `ADMIN_PASSWORD` fort, `AUTH_SECRET_KEY`,
   `OTP_PEPPER`, `CONTACTS_ENCRYPTION_KEY`, `POSTGRES_USER`, `POSTGRES_DB` et
   `POSTGRES_PASSWORD`.
3. Configurez `CORS_ORIGINS` avec les origines exactes du navigateur et placez le
   service derrière un reverse proxy HTTPS. Gardez `COOKIE_SECURE=true` en production.
4. Lancez `docker compose up --build -d`. Le port est lié à `127.0.0.1:8000` par
   défaut; le reverse proxy local peut le joindre. Les données PostgreSQL persistent
   dans le volume `postgres_data`.

Ne publiez pas directement le port applicatif sur Internet. Utilisez un gestionnaire
de secrets pour l'exploitation; le fichier `.env` de Compose convient uniquement à
un environnement maîtrisé et doit être protégé. Sauvegardez et testez la restauration
de PostgreSQL. Les changements de schéma sont actuellement appliqués par
`CREATE TABLE IF NOT EXISTS` et une migration additive ciblée; planifiez des
migrations versionnées avant les mises à jour de production.

Pour revenir à HTTP local derrière Docker, définissez explicitement
`COOKIE_SECURE=false` dans `.env` et utilisez uniquement une interface locale de
confiance. Ne faites pas ce réglage sur une instance accessible publiquement.

## Configurer les fournisseurs

### Notifications

- **SMS Twilio** : `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` et `TWILIO_FROM_NUMBER`.
- **Telegram** : `TELEGRAM_BOT_TOKEN` et l'identifiant de conversation Telegram
  correspondant, enregistré comme destination chiffrée.
- **FCM** : `FCM_SERVICE_ACCOUNT_FILE` doit désigner un fichier de compte de service
  Firebase accessible en lecture par le processus, et le jeton d'appareil du client
  doit être enregistré. Avec Compose, placez le fichier sous
  `secrets/firebase-service-account.json` (ou modifiez `FCM_SERVICE_ACCOUNT_FILE` et
  le volume); le dossier est monté en lecture seule sous `/run/secrets`. Ne l'ajoutez
  jamais à l'image ni au dépôt.
- Ajoutez les destinations avec `PUT /api/client-hub/contacts` (rôle senior requis).
  Elles sont chiffrées au repos par la clé `CONTACTS_ENCRYPTION_KEY`. Sauvegardez cette
  clé séparément : sa perte rend les destinations stockées irrécupérables.

Un service non configuré ou une erreur du fournisseur produit une erreur HTTP, jamais
un faux état de livraison. Les connexions réelles doivent être validées dans les
comptes de test des fournisseurs avant tout envoi client.

### Ingestion de transactions

`POST /api/transactions` peut être appelé par un opérateur authentifié ou par un
service avec l'en-tête `X-API-Key`, si `TRANSACTION_INGESTION_API_KEY` contient une
clé d'au moins 32 caractères. Gardez cette clé hors du navigateur et du dépôt.

### Synchronisation fédérée

Configurez un `FEDERATION_NODE_ID`, `FEDERATED_PEERS` comme tableau JSON de partenaires
HTTPS avec secrets HMAC partagés, et `FEDERATION_TRUSTED_PEERS` comme objet JSON des
partenaires autorisés à envoyer des mises à jour. Utilisez des secrets aléatoires
distincts par partenaire et échangez-les par un canal sécurisé. Les seuils entrants
restent en attente d'approbation senior.

### Services optionnels

- `GROQ_API_KEY` active l'analyse cloud; l'envoi d'agrégats ne s'active qu'avec
  `GROQ_ALLOW_ANONYMIZED_AGGREGATES=true`.
- Neo4j nécessite `NEO4J_URI`, `NEO4J_USERNAME` et `NEO4J_PASSWORD`.
- La vérification Groth16 nécessite `ZK_VERIFICATION_KEY_PATH` et `snarkjs` accessibles
  dans l'environnement. Sans ces éléments, l'API signale explicitement que le
  vérificateur n'est pas configuré.

## Routes utiles

| Méthode | Route | Accès / fonction |
|---|---|---|
| `GET` | `/health` | Santé du processus |
| `POST` | `/api/auth/login` | Connexion opérateur |
| `GET`, `POST` | `/api/auth/operators` | Gestion des opérateurs, senior |
| `GET`, `POST` | `/api/transactions` | Lecture opérateur; ingestion opérateur ou clé de service |
| `POST` | `/api/client-hub/send-challenge` | Envoi d'un défi, opérateur |
| `POST` | `/api/client-hub/respond` | Réponse du client à un défi OTP |
| `PUT` | `/api/client-hub/contacts` | Destinations chiffrées, senior |
| `POST` | `/api/self-healing/rules/{id}/approve` | Approbation d'une règle, senior |
| `POST` | `/api/self-healing/rules/{id}/veto` | Veto d'une règle, senior |
| `POST` | `/api/federated/sync` | Synchronisation sortante, senior |
| `POST` | `/api/federated/receive` | Réception fédérée authentifiée HMAC |
| `WS` | `/ws/live-soc` | Flux temps réel, session opérateur requise |

Les routes opérateur, l'état de santé et les éléments exposés par le navigateur ne
doivent pas être considérés comme un remplacement d'une architecture de déploiement,
d'une supervision opérationnelle et d'un audit de sécurité indépendants.
