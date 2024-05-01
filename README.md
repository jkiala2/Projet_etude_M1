# PROJET D'ETUDE
```
 ____  ____   ___      _ _____ _____   _____ _   _ _____ ______   __
|  _ \|  _ \ / _ \    | | ____|_   _| |_   _| | | |_   _|  _ \ \ / /
| |_) | |_) | | | |_  | |  _|   | |     | | | | | | | | | |_) \ V /
|  __/|  _ <| |_| | |_| | |___  | |     | | | |_| | | |_|  __/ | |
|_|   |_| \_\\___/ \___/|_____| |_|     |_|  \___/  |_(_)_|    |_|
```
## Présentation

Ce script Python a pour butd'automatiser le scan d'un réseau et de découvrir toutes les vulnérabilités des hôtes présents sur ce réseau.
Si le port 22 du protocole SSH est ouvert, le script lance un bruteforce pour tenter d'obtenir les identifiants de connexion pour établir une connexion SSH (pareil pour le protocole FTP si le port 21 est ouvert).

Ce script est réalisé dans le cadre du projet d'étude en M1 à Sup de Vinci.

## Fonctionnalitées

<p align="center">
  <img src="schéma.png" style="width: 60%;">
</p>

- Scan du réseau et identifie tous les hôtes.
- Scan des ports de chacun des hôtes précédemment découvert (scan de vulnérabilités avec Nmap).
- Analyse des vulnérabilités via les codes CVE-20XX-XXXX.
- Bruteforce SSH si le port 22 est ouvert.
- Bruteforce FTP si le port 21 est ouvert.

### Disclaimer
Cet outil ne peut être utilisé qu'à des fins légales. Les utilisateurs assument l'entière responsabilité de toute action effectuée à l'aide de cet outil. L'auteur décline toute responsabilité pour les dommages causés par cet outil. Si ces termes ne vous conviennent pas, n'utilisez pas cet outil.

## Installation

1. Clonez le `repository` à l'aide de la commande : 
```bash
git clone https://github.com/jkiala2/Projet_etude_M1
```

2. Pour installer les modules python, executez la commande : 
```bash
pip install -r requirements.txt
```

## Utilisation

1. Lancez le script :
    - En cliquant sur le fichier `Start.bat`.
    - Avec la commande :
        ```bash
        py projet-tut.py
        ```
2. Entrez une adresse IP connue sur le réseau que vous souhaitez scanner **ou** appuyez sur ENTRER (cela utilisera votre adresse IP locale).
3. Entrez le code CVE qui s'affichera à la fin de l'analyse Nmap.
4. Vous trouverez dans le dossier `scan/`, des fichiers de journalisations JSON (logs) de l'analyse Nmap de tous les hôtes déjà scannés.
5. Vous trouverez dans le dossier `cve/`, le résumé du rapport CVE au format JSON.

## Démonstration et expliquations

```
 ____  ____   ___      _ _____ _____   _____ _   _ _____ ______   __
|  _ \|  _ \ / _ \    | | ____|_   _| |_   _| | | |_   _|  _ \ \ / /
| |_) | |_) | | | |_  | |  _|   | |     | | | | | | | | | |_) \ V /
|  __/|  _ <| |_| | |_| | |___  | |     | | | |_| | | |_|  __/ | |
|_|   |_| \_\\___/ \___/|_____| |_|     |_|  \___/  |_(_)_|    |_|


Entrer une adresse IP (l'adresse IP de cette machine est par défaut :
192.168.1.1, pour la selectionner appuyez sur ENTRER).
>
```

Le scan du réseau commence alors ici. Il va nous montrer tous les ports et services disponibles sur votre réseau


```
Scan réseau en cours ...
==================================================
Hôte    192.168.1.1     up
Hôte    192.168.1.125   up
==================================================
```

Suite au scan complet du réseau, le script va lancer un scan Nmap sur chaque hôte.

Paramètres du scan :
- `-sV` : Sonde les ports ouverts pour déterminer les informations de service/version.
- `-p 20-450` : Analyser uniquement les ports spécifiés (du 22 au 450).
- `--script="vuln and safe"` : Utilise un script qui analyse les vulnérabilités d'un service.

Premier hôte :
```
Début du scan Nmap pour :       192.168.56.1      
PORT    STATE   SERVICE
22/tcp  open    ssh
| Product: sshd
| Script:
| Version:
135/tcp open    msrpc
| Product: Microsoft Windows RPC
| Script:
| Version:
139/tcp open    netbios-ssn
| Product: Microsoft Windows netbios-ssn
| Script:
| Version:
445/tcp open    microsoft-ds
| Product:
| Script:
| Version:

Analyse Nmap finie pour 192.168.56.1: 1 hôte scanné en 79.06s.
```

Deuxième hôte :
```
Début du scan Nmap pour :       192.168.1.125     
PORT    STATE   SERVICE
80/tcp  open    http
| Product: Apache httpd
| Script:
| | http-server-header: Apache/2.4.46 (Win64) PHP/7.3.21
| | http-slowloris-check:
  VULNERABLE:
  Slowloris DOS attack
    State: LIKELY VULNERABLE
    IDs:  CVE:CVE-2007-6750
      Slowloris tries to keep many connections to the target web server open and hold
      them open as long as possible.  It accomplishes this by opening connections to
      the target web server and sending a partial request. By doing so, it starves
      the http server's resources causing Denial Of Service.

    Disclosure date: 2009-09-17
    References:
      http://ha.ckers.org/slowloris/
      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750

| | http-trace: TRACE is enabled
| | http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| | vulners:
  cpe:/a:apache:http_server:2.4.46:
        E899CC4B-A3FD-5288-BB62-A4201F93FDCC    10.0    https://vulners.com/githubexploit/E899CC4B-A3FD-5288-BB62-A4201F93FDCC  *EXPLOIT*
        5DE1B404-0368-5986-856A-306EA0FE0C09    10.0    https://vulners.com/githubexploit/5DE1B404-0368-5986-856A-306EA0FE0C09  *EXPLOIT*
        CVE-2022-23943  7.5     https://vulners.com/cve/CVE-2022-23943
        CVE-2022-22720  7.5     https://vulners.com/cve/CVE-2022-22720
        CVE-2021-44790  7.5     https://vulners.com/cve/CVE-2021-44790
        CVE-2021-39275  7.5     https://vulners.com/cve/CVE-2021-39275
        CVE-2021-26691  7.5     https://vulners.com/cve/CVE-2021-26691
        FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8    6.8     https://vulners.com/githubexploit/FDF3DFA1-ED74-5EE2-BF5C-BA752CA34AE8  *EXPLOIT*
        CVE-2022-22721  6.8     https://vulners.com/cve/CVE-2022-22721
        CVE-2021-40438  6.8     https://vulners.com/cve/CVE-2021-40438
        CVE-2020-35452  6.8     https://vulners.com/cve/CVE-2020-35452
        8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2    6.8     https://vulners.com/githubexploit/8AFB43C5-ABD4-52AD-BB19-24D7884FF2A2  *EXPLOIT*
        4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332    6.8     https://vulners.com/githubexploit/4810E2D9-AC5F-5B08-BFB3-DDAFA2F63332  *EXPLOIT*
        CVE-2021-44224  6.4     https://vulners.com/cve/CVE-2021-44224
        CVE-2022-22719  5.0     https://vulners.com/cve/CVE-2022-22719
        CVE-2021-36160  5.0     https://vulners.com/cve/CVE-2021-36160
        CVE-2021-34798  5.0     https://vulners.com/cve/CVE-2021-34798
        CVE-2021-33193  5.0     https://vulners.com/cve/CVE-2021-33193
        CVE-2021-30641  5.0     https://vulners.com/cve/CVE-2021-30641
        CVE-2021-26690  5.0     https://vulners.com/cve/CVE-2021-26690
        CVE-2020-9490   5.0     https://vulners.com/cve/CVE-2020-9490
        CVE-2020-13950  5.0     https://vulners.com/cve/CVE-2020-13950
        CVE-2019-17567  5.0     https://vulners.com/cve/CVE-2019-17567
| Version: 2.4.46
135/tcp open    msrpc
| Product: Microsoft Windows RPC
| Script:
| Version:
139/tcp open    netbios-ssn
| Product: Microsoft Windows netbios-ssn
| Script:
| Version:

Analyse Nmap finie pour 192.168.1.125: 1 hôte scanné en 117.03s.

```

Ici, on remarque que le script `"vuln and safe"` a trouvé une vulnérabilité.

```
Saisissez un code CVE pour votre recherche:
>CVE-2007-6750
```

Suite à cela, le script vous demandera le code CVE pour vous ressortir le résultat correspondant à ce code au format JSON dans le dossier `cve/`.


De plus, comme le port SSH (22) est ouvert sur le premier hôte, le script va lancer un bruteforce. Il vous sera demandé de fournir un nom d'utilisateur (identifiant de connexion pour le SSH, dans cet exemple ça sera `username`) ainsi qu'un dictionnaire de mots de passe (nous utiliserons une version allégée du dictionnaire `rockyou.txt`).

```
PORT 22 OUVERT
Entrer un nom d'utilisateur :
>username
Entrer un dictionnaire de mots de passe (juste le nom du fichier, sans l'extension) :
>rockyou
```
Si un mot de passe est trouvé, il vous le retournera (comme ci-dessous).

```
Mot de passe trouvé : password123
```

##### Développé par [Jeremie KIALA ](https://github.com/jkiala2/Projet_etude_M1).
###### Autres ressources : [PyCVESearch](https://github.com/cve-search/PyCVESearch).
