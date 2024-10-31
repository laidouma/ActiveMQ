Voici le texte formaté en Markdown (`README.md`) pour GitHub :

```markdown
# Configuration de l'environnement ActiveMQ 2015

## Résumé des commandes
1. **Naviguer vers le dossier `activemq_2015`**  
   ```bash
   cd activemq_2015
   ```

2. **Lancer le conteneur Docker**  
   ```bash
   docker-compose up -d
   ```
   Cette commande démarre le service ActiveMQ en mode détaché.

   **Résultat attendu** :
   ```
   Starting activemq_2015_activemq_1 … done
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

## Scan réseau de ActiveMQ_2015

- **Adresse IP identifiée** : `172.18.0.1`
- **Scan de ports** : Un scan réseau révèle les ports ouverts pour les services hébergés sur cette adresse IP.

   ```bash
   nmap 172.18.0.* -p 1-65535
   ```
   - **Ports d'intérêt** :
     - **8161** (pour la console Web ActiveMQ)

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

---

## Vulnérabilité CVE : CVE-2015-1830

### Détails de la vulnérabilité
- **Description** : Une vulnérabilité de type "traversée de répertoire" dans la fonctionnalité de téléchargement/téléversement de fichiers pour les messages blob dans ActiveMQ (versions 5.x avant 5.11.2) sur Windows permet aux attaquants distants de créer des fichiers JSP dans des répertoires arbitraires.
- **Impact** : Les attaquants peuvent potentiellement exécuter du code malveillant en créant des fichiers dans des répertoires non sécurisés.
- **Score CVSS** : 5.0 (Moyen)

### Stratégie d’exploitation
1. **Objectif** : Exploiter la vulnérabilité de traversée de répertoire pour obtenir un accès non autorisé ou exécuter du code arbitraire.
2. **Approche** :
   - Exploiter la fonctionnalité de téléversement de messages blob pour placer des fichiers JSP malveillants dans des répertoires sensibles.
   - Utiliser des requêtes spécialement conçues pour manipuler les chemins de fichiers et éventuellement exécuter du code à distance sur des systèmes Windows vulnérables avec ActiveMQ en version inférieure à 5.11.2.

---

## Mesures de sécurité

Pour atténuer cette vulnérabilité :
1. **Mettre à jour ActiveMQ** : Assurez-vous qu’ActiveMQ est mis à jour vers la version 5.11.2 ou une version plus récente pour éviter l’exposition à la CVE-2015-1830.
2. **Sécurité réseau** : Restreignez l’accès à la console de gestion ActiveMQ en appliquant des règles de réseau ou des configurations de pare-feu.
3. **Contrôle d’accès** : Utilisez des mots de passe forts pour la console d'administration ActiveMQ et évitez les identifiants par défaut.

---

Cette configuration et analyse de sécurité fournit un guide pour la mise en place et le scan de l’environnement ActiveMQ 2015, ainsi qu'une compréhension des implications des vulnérabilités spécifiques. Ce document peut être ajouté en tant que fichier README dans votre dépôt GitHub.
```

---
