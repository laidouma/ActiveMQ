# Configuration de l'environnement ActiveMQ 2016

## Résumé des commandes

1. **Naviguer vers le dossier `activemq_2016`**
   ```bash
   cd activemq_2016
   ```

2. **Lancer le conteneur Docker**
   ```bash
   docker-compose up -d
   ```
   Cette commande démarre le service ActiveMQ en mode détaché.

   **Résultat attendu** :
   ```
   Starting activemq_2016_activemq_1 … done
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

## Scan réseau de ActiveMQ_2016

- **Adresse IP identifiée** : `172.19.0.1`
- **Scan de ports** : Un scan réseau révèle les ports ouverts pour les services hébergés sur cette adresse IP.

   ```bash
   nmap 172.19.0.* -p 1-65535
   ```
   - **Ports d'intérêt** :
     - **8161** (pour la console Web ActiveMQ)
       
![Capture d'écran 2024-10-31 124105](https://github.com/user-attachments/assets/d68dc28c-bf47-43a5-9a29-d95e79e22dff)

---

## Accéder à la console ActiveMQ

Après avoir identifié l’adresse IP et les ports ouverts, accédez à l’interface web d’ActiveMQ :

1. **Naviguer vers** : [http://localhost:8161](http://localhost:8161)
2. **Identifiants de connexion** :
   - **Nom d’utilisateur** : `admin`
   - **Mot de passe** : `admin`

### Informations sur la version d’ActiveMQ

- La **version d’ActiveMQ** peut être confirmée sur le tableau de bord principal après connexion. Dans ce cas :
   - **Version** : `5.11.1`

![Capture d'écran 2024-10-31 124136](https://github.com/user-attachments/assets/3fc87f14-611d-4ab9-9e54-b456a2aad7b6)

---

## Vulnérabilité CVE : CVE-2016-0782

![Capture d'écran 2024-10-31 124229](https://github.com/user-attachments/assets/a1daade0-11fb-4c21-ae2b-9389cb6eee70)

### Détails de la vulnérabilité
- **Description** : La vulnérabilité CVE-2016-0782 permet une exécution de code à distance en exploitant une faille dans la configuration des droits d'accès d'ActiveMQ. Cette vulnérabilité se produit en raison de l'absence de contrôle d'accès adéquat sur certaines opérations d'administration.
- **Impact** : Les attaquants peuvent potentiellement exécuter des commandes arbitraires sur le serveur vulnérable.

---

## Stratégie d’exploitation

1. **Objectif** : Exploiter la vulnérabilité de contrôle d'accès pour obtenir un accès non autorisé ou exécuter du code arbitraire.
2. **Approche** :
   - Envoyer des requêtes non authentifiées pour manipuler la configuration du serveur ou exécuter des commandes arbitraires.
   - Utiliser des requêtes spécialement conçues pour contourner les contrôles d'accès d'ActiveMQ en version inférieure à 5.12.

---

# Stratégie de Compromission

## Code d'exploitation Metasploit pour ActiveMQ

```ruby
CVE-2016-0782: ActiveMQ Web Console - Cross-Site Scripting

Severity: Important

Vendor:
The Apache Software Foundation

Versions Affected:
Apache ActiveMQ 5.0.0 - 5.13.0

Description:
Several instances of cross-site scripting vulnerabilities were identified to be present in the web based administration console as well as the ability to trigger a Java memory dump into an arbitrary folder. The root cause of these issues are improper user data output validation and incorrect permissions configured on Jolokia.


Mitigation:
Upgrade to Apache ActiveMQ 5.11.4, 5.12.3, or 5.13.1

Credit:
This issue was discovered by Vladimir Ivanov (Positive Technologies)

```

---

