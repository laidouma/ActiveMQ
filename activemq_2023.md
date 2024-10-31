# Configuration de l'environnement ActiveMQ 2023

## Résumé des commandes

1. **Naviguer vers le dossier `activemq_2023`**
   ```bash
   cd activemq_2023
   ```

2. **Lancer le conteneur Docker**
   ```bash
   docker-compose up -d
   ```
   Cette commande démarre le service ActiveMQ en mode détaché.

   **Résultat attendu** :
   ```
   Starting activemq_2023_activemq_1 … done
   ```

3. **Lister les conteneurs Docker actifs**
   ```bash
   docker container ls
   ```
   Cette commande permet de vérifier que le conteneur `ActiveMQ` est bien en cours d'exécution.

4. **Récupérer l'adresse IP du conteneur**
   ```bash
   ip a
   ```
   Cette commande affiche la configuration réseau pour identifier l'adresse IP.

---

## Scan réseau de ActiveMQ_2023

- **Adresse IP identifiée** : `172.21.0.1`
- **Scan de ports** : Un scan réseau révèle les ports ouverts pour les services hébergés sur cette adresse IP.

   ```bash
   nmap 172.21.0.* -p 1-65535
   ```
   - **Ports d'intérêt** :
     - **8161** (pour la console Web ActiveMQ)

![Capture d'écran 2024-10-31 134805](https://github.com/user-attachments/assets/2070146e-ae74-4d5b-9997-ea1b0f32406b)


---

## Accéder à la console ActiveMQ

Après avoir identifié l’adresse IP et les ports ouverts, accédez à l’interface web d’ActiveMQ :

1. **Naviguer vers** : [http://localhost:8161](http://localhost:8161)
2. **Identifiants de connexion** :
   - **Nom d’utilisateur** : `admin`
   - **Mot de passe** : `admin`

### Informations sur la version d’ActiveMQ

- La **version d’ActiveMQ** peut être confirmée sur le tableau de bord principal après connexion. Dans ce cas :
   - **Version** : `5.17.3`
     
![Capture d'écran 2024-10-31 134913](https://github.com/user-attachments/assets/2a9fb90e-6059-4c7f-8d04-25989d59044b)

---

## Vulnérabilité CVE : CVE-2023-31056

![Capture d'écran 2024-10-31 135027](https://github.com/user-attachments/assets/0b51f3be-32bf-49e9-be11-e841522fd03f)

### Détails de la vulnérabilité
- **Description** : La vulnérabilité CVE-2023-31056 permet une exécution de code à distance en exploitant une faille dans la configuration des droits d'accès d'ActiveMQ. Cette vulnérabilité se produit en raison de l'absence de contrôle d'accès adéquat sur certaines opérations d'administration.
- **Impact** : Les attaquants peuvent potentiellement exécuter des commandes arbitraires sur le serveur vulnérable.

---

## Stratégie d’exploitation

1. **Objectif** : Exploiter la vulnérabilité de contrôle d'accès pour obtenir un accès non autorisé ou exécuter du code arbitraire.
2. **Approche** :
   - Envoyer des requêtes non authentifiées pour manipuler la configuration du serveur ou exécuter des commandes arbitraires.
   - Utiliser des requêtes spécialement conçues pour contourner les contrôles d'accès d'ActiveMQ en version inférieure à 5.18.

---
