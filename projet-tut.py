import nmap
import socket
import json
import pyfiglet
import paramiko
import sys
import time
from pycvesearch import CVESearch
from threading import Thread
from ftplib import FTP

class Network(object):
    def __init__(self):
        print("\033[1m" + pyfiglet.figlet_format("PROJET D'ETUDE") + "\033[0m")
        self.ip = input(f"\033[96mEntrer une adresse IP (l'adresse IP de cette machine est par défaut :\n{socket.gethostbyname(socket.gethostname())}, pour la sélectionner, appuyez sur ENTRER).\n> \033[0m")
        self.hosts = []
        self.nm = nmap.PortScanner()
        self.cve = CVESearch(base_url='https://cve.circl.lu')
    
    def section_print(self, title):
        print("\n\033[1m" + "=" * 50)
        print(title)
        print("=" * 50 + "\033[0m\n")

    def network_scanner(self):
        if len(self.ip) == 0:
            network = f"{socket.gethostbyname(socket.gethostname())}/24"
        else:
            network = self.ip + '/24'
        
        print("\033[96m\nScan réseau en cours ...\033[0m")
        self.nm.scan(hosts=network, arguments="-sn")
        hosts_list = [(x, self.nm[x]['status']['state']) for x in self.nm.all_hosts()]

        print("\033[1m" + "=" * 50)
        for host, status in hosts_list:
            print("\033[93mHôte\t{}\t{}\033[0m".format(host, status))
            self.hosts.append(host)
        print("=" * 50 + "\033[0m")
    
    def nmap_scan(self, host):
        print(f"\n\033[96mDébut du scan Nmap pour :\t{host}\033[0m")
        scan_result = self.nm.scan(hosts=host, arguments='-sV -p 20-450 --script="vuln and safe"')
        
        with open(f"scan/{host}.csv", "w", encoding="utf-8") as f:
            f.write(self.nm.csv())

        with open(f"scan/{host}.json", "w", encoding="utf-8") as f:
            f.write(json.dumps(scan_result, indent=4, sort_keys=True))
    
    def print_result(self, host):
        print("\033[1mHostname : {}\033[0m".format(self.nm[host].hostname()))
        print("\033[1mPORT\tSTATE\tSERVICE\033[0m")
        for i in range(20, 450):
            try:
                if self.nm[host]["tcp"][i]:
                    print("{}/tcp\t{}\t{}".format(i, self.nm[host]["tcp"][i]["state"], self.nm[host]["tcp"][i]["name"]))
                    print(" | Product : {}".format(self.nm[host]["tcp"][i]["product"]))
                    if self.nm[host]["tcp"][i]["script"]:
                        print(" | Script :")
                        for script in self.nm[host]["tcp"][i]["script"]:
                            print(" | | {} : {}".format(script, self.nm[host]["tcp"][i]["script"][script]))
                    print(" |_Version : {}".format(self.nm[host]["tcp"][i]["version"]))
            except:
                pass
        print("\n\033[1mAnalyse Nmap finie pour {}.\033[0m".format(host))

    def cve_finder(self):
        try:
            cve_entry = str(input("\n\033[96mSaisissez un code CVE pour votre recherche:\n> \033[0m"))
            cve_result = self.cve.id(cve_entry)

            with open(f"cve/{cve_entry}.json", "w", encoding="utf-8") as f:
                f.write(json.dumps(cve_result, indent=4, sort_keys=True))
        except:
            pass
    
    def ssh_connect(self, ip, username, password, port=22):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, port, username, password)
            print("\033[92mMot de passe trouvé : " + password + "\033[0m")
            return True
        except:
            return False

    def ftp_connect(self, ip, user, password):
        try:
            FTP(ip, user=user, passwd=password)
            print("\033[92mMot de passe trouvé : " + password + "\033[0m")
            return True
        except:
            return False

    def bruteforce(self, ip, type):
        username = str(input("\033[96mEntrer un nom d'utilisateur :\n> \033[0m"))
        wordl = str(input("\033[96mEntrer un dictionnaire de mots de passe (juste le nom du fichier, sans l'extension) :\n> \033[0m"))

        with open(f"wordlists/{wordl}.txt", 'r', encoding="utf8") as file:
            for line in file.readlines():
                if type == "ssh":
                    th = Thread(target=self.ssh_connect, args=(ip, username, line.strip()))
                    th.start()
                elif type == "ftp":
                    th = Thread(target=self.ftp_connect, args=(ip, username, line.strip()))
                    th.start()

    def service_detection(self, host):
        if self.nm[host].has_tcp(22):
            print("\n\033[93mHôte\t{}\nPort ssh (22) ouvert.\nLancement d'un bruteforce sur cet hôte.\033[0m".format(host))
            self.bruteforce(host, "ssh")
        elif self.nm[host].has_tcp(21):
            print("\n\033[93mHôte\t{}\nPort ftp (21) ouvert.\nLancement d'un bruteforce sur cet hôte.\033[0m".format(host))
            self.bruteforce(host, "ftp")

    def projet_tut(self):
        self.network_scanner()
        print("\n\033[96mLe scan du réseau commence alors ici. Il va nous montrer tous les ports et services disponibles sur votre réseau).\033[0m")
        for host in self.hosts:
            self.nmap_scan(host)
            self.print_result(host)
        print("\n\033[96mSuite au scan complet du réseau, le script va lancer un scan Nmap sur chaque hôte.\033[0m")
        time.sleep(1)
        self.cve_finder()
        print("\n\033[96mIci, on remarque que le script \"vuln and safe\" a trouvé une vulnérabilité.\033[0m")
        time.sleep(1)

if __name__ == "__main__":
    try:
        Nscan = Network()
        Nscan.projet_tut()
    except KeyboardInterrupt:  
        print("\n\033[91m[x] Fermeture du programme !\033[0m")
        sys.exit()
