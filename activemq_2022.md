# Configuration de l'environnement ActiveMQ 2022

## Résumé des commandes

1. **Naviguer vers le dossier `activemq_2022`**
   ```bash
   cd activemq_2022
   ```

2. **Lancer le conteneur Docker**
   ```bash
   docker-compose up -d
   ```
   Cette commande démarre le service ActiveMQ en mode détaché.

   **Résultat attendu** :
   ```
   Starting activemq_2022_activemq_1 … done
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

## Scan réseau de ActiveMQ_2022

- **Adresse IP identifiée** : `172.20.0.1`
- **Scan de ports** : Un scan réseau révèle les ports ouverts pour les services hébergés sur cette adresse IP.

   ```bash
   nmap 172.20.0.* -p 1-65535
   ```
   - **Ports d'intérêt** :
     - **8161** (pour la console Web ActiveMQ)
       
![Capture d'écran 2024-10-31 132500](https://github.com/user-attachments/assets/f02616c1-2859-4d03-8872-0e5504b37f78)

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

![Capture d'écran 2024-10-31 132524](https://github.com/user-attachments/assets/d8b29f9f-e861-45a0-aaa9-92766e6dd6d5)

---

## Vulnérabilité CVE : CVE-2022-29582

![Capture d'écran 2024-10-31 132833](https://github.com/user-attachments/assets/4f153c30-3b1d-400c-be3d-7c5792ee295a)

### Détails de la vulnérabilité
- **Description** : La vulnérabilité CVE-2022-29582 dans ActiveMQ permet une injection de commande à distance, permettant aux attaquants de contourner les restrictions d'accès et d'exécuter des commandes sur le système hôte.
- **Impact** : Les attaquants peuvent obtenir un accès à distance au serveur et exécuter des commandes arbitraires avec les privilèges de l'application ActiveMQ.
- **Score CVSS** : 7.0 (High)

---

## Stratégie d’exploitation

1. **Objectif** : Exploiter la vulnérabilité d'injection de commande pour obtenir un accès non autorisé ou exécuter du code arbitraire.
2. **Approche** :
   - Envoyer des requêtes malveillantes pour manipuler les commandes de l'interface d'administration.
   - Exploiter l'absence de contrôles d'accès appropriés pour exécuter des commandes sur le serveur hôte.

---

# Stratégie de Compromission

```ruby
https://github.com/torvalds/linux/commit/e677edbcabee849bfdd43f1602bccbecf736a646
```

---
