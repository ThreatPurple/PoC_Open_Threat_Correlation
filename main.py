import requests
import pathlib
import sys
import os
import pandas as pd
import re
#import pdb
#import csv
import time 
from datetime import datetime
from tkinter import filedialog 
from tkinter import *
#from openpyxl import Workbook
#from openpyxl.styles import PatternFill #pour colorier le DataFrame
from openpyxl.utils.dataframe import dataframe_to_rows

#installer le module xlrd pour prendre en charche les fichier exel
api_key_VT = str(input("API KEY VT : "))
url_abuse = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

path_file_bdd = "abuse/sslipblacklist.csv"

def compare_with_abuse() :
    df_abuse = pd.read_csv(path_file_bdd,  delimiter=",", names=["Date de signalement","IP","Port de Destination", "Explication"])
    df_VT = pd.read_excel("Output_Script.xlsx")
    positions_match = []

    # Itération sur les index et valeurs des deux DataFrames
    for index_df1, valeur_df_abuse in df_abuse["IP"].items():
        for index_df2, valeur_df_VT in df_VT["IP"].items():
            # Comparaison des valeurs
            if valeur_df_abuse == valeur_df_VT:
                # Ajouter la position du match à la liste
                positions_match.append((index_df1, index_df2))

    # jécris dans la colonne commentaire des DataFrames
    for index_df1, index_df2 in positions_match:
        df_VT.at[index_df1, "Comment"] = "Cette adresse IP est un serveur C2 Malveillant \n source Abuse CH"
        df_VT.at[index_df1, "Score"] = 5
    
    print("voila DataFrame_VT : ", df_VT)
    #df_VT.to_excel("Test_Output_Script.xlsx", index=False)
    #style_df = pd.read_excel("Test_Output_Script.xlsx")
    print("Colorization in progress...")

    df_color = df_VT.style.applymap(color_cell, subset=["Score"])
    df_color.to_excel("Test_Output_Script.xlsx", index=False)
    print("Finish !")
    #for element in liste_VT:
    #    if element in liste_abuse:
    #        match.append(element)
    #        print(match)

    #correspondance = df_VT["IP"].isin(liste_abuse)
    #print(correspondance)



def clear_abuse_response():
    """si une ligne contient "#" alors je la supprime 
    a la fin il ne dois me reste que des ligne séparer par des "," pour que je puisse charger correctement le CSV """
    with open(path_file_bdd, 'r') as file:
        lignes = file.readlines()

    #j'enregistre que les lignes qui ne commence pas par '#'
    lignes_modifiees = [ligne for ligne in lignes if not ligne.startswith("#")]

    with open(path_file_bdd, 'w') as file:
        file.writelines(lignes_modifiees)
    print(" \n [+] Fichier modifié avec succès !")
    return 0


def check_bdd_abuse():

    if os.path.isdir("abuse"):#je vérifie si le dossier abuse exsiste
        if os.path.isfile(path_file_bdd):
            """ Je vérifie si le fichier exsiste si il exsiste depuis +5 minutes je télécharge une nouvelle version """
            print("BDD abuse exsiste depuis: ")
            #temps de création du fichier 
            file_temp = os.path.getmtime(path_file_bdd)
            diff_time = time.time() - file_temp
            diff_minute = diff_time / 60

            if diff_minute > 5: #si el fichier exsiste depuis + de 5 minutes alors je télécharge la nouvelles version 
                try:
                    print("[+] le fichier n'exsiste pas \n[+]tentative de telechargement ")
                    response = requests.get(url=url_abuse)
                    open(path_file_bdd, "wb").write(response.content)
                    print("[+] téléchargement réussie \n[+] nettoyage du fichie")
                    clear_abuse_response() #je vais nettoyer le fichier reçu en enlevant les #
                except:
                    print("je n'est pas réussi a télécharger la nouvelle version du fichier \n utilisation de l'ancienne version qui date du {}".format(datetime.fromtimestamp(file_temp)))
                    pass

        else: #si le fichier n'exsiste pas alors je le télécharge
            print("[+] le fichier n'exsiste pas \n tentative de telechargement ")
            response = requests.get(url=url_abuse)
            open(path_file_bdd, "wb").write(response.content)
            print("[+] téléchargement réussie \n [+] nettoyage du fichie")
            clear_abuse_response() #je vais nettoyer le fichier reçu en enlevant les #
    else:
        print(""" [+] création du dossier "abuse" """)
        os.mkdir("abuse")
        check_bdd_abuse()
        return 0


def gui_excel_file():
    filename = filedialog.askopenfilename(initialdir= "/",title="Select Excel File",filetypes=(("Excel files","*.xlsx"),("CSV files","*.csv*"))) 
    extension_file = pathlib.Path(filename).suffix
    
    if extension_file == ".xlsx" or ".csv":
        return [filename, extension_file]
    else:
        print("Erreur dans le programme")
        sys.exit()

def open_excel_file(file_info):#retourne une DataFrame du fichier Excel
    path_file = file_info[0]
    extension_file = file_info[1]
    if extension_file == ".xlsx":
        data_frame = pd.read_excel(path_file, engine='openpyxl', usecols=["IP", "DOMAIN"])
        #gui_head_file(data_frame.columns)
        return data_frame
    elif extension_file == ".csv":
        data_frame = pd.read_csv(path_file, usecols=["IP", "DOMAIN"])
        return data_frame
    
def color_cell(x):
    try:
        if x < 2:
            return "background-color: lightgreen"
        elif 2 <= x == 3 :
            return "background-color: yellow"
        elif x > 3:
            return "background-color: red"
    except TypeError:
        pass
        

def print_to_excel(json_data: list):
    df = pd.DataFrame(data=json_data, columns=["IP", "AS Owner", "Country","DNS Owner", "Score", "Comment"]) #ci je produit et hordonne ma DataFrame
    print(df)

    df.to_excel("Output_Script.xlsx", index=False)
    print("[+] Result Product!")

    style_df = pd.read_excel("Output_Script.xlsx")
    print("Colorization in progress...")

    df_color = style_df.style.applymap(color_cell, subset=["Score"])
    df_color.to_excel("Output_Script.xlsx", index=False)
    print("Finish !")
    #classeur.save("Output_Script.xlsx")

def regex_whois(texte_whois: str):
    regex = r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
    resultats = re.search(regex, texte_whois)

    if resultats:
        domaine = resultats.group()
        return domaine
    else:
        return ""


def get_domain_reputation(domain):
    url = "https://www.virustotal.com/api/v3/domains/{}".format(domain)
    headers_VT_domain_reputation = {
    "accept": "application/json",
    "x-apikey": api_key_VT
    }
    response = requests.get(url, headers=headers_VT_domain_reputation)
    response = response.json()
    return response

def get_ip_reputation(ip_addres: str):
    url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip_addres)
    headers_VT_ip_reputation = {
    "accept": "application/json",
    "x-apikey": api_key_VT
    }
    response = requests.get(url, headers=headers_VT_ip_reputation)
    response_json = response.json()#je recupere la réponse du serveur en version JSON
    response_data = search_info(response_json, ip_addres) #je vais chercher les informations que je desire dans ma réponse json
    return response_data

def scoring(scoring_list): #algorithme de pondération des différentes notes 
    weight_harmless =  1 # par scanner qui le détecte comme innofensif le score baise de 25%
    weight_malicious = 5 #par scanner qui le détecte comme malicieux le score augmente de 100%
    weight_suspicious = 3 #par scanner qui le détecte comme suspicieux le score augmente de 40%
    weight_undetected = 0 #les scanner ne connaissent pas cette adresse IP
    #je définis les poids pour chaque élément
    poids = [-0.75,5,3,0]

    ponderation_sum = sum([scoring_list[i] * poids[i] for i in range(3)])
    note = (ponderation_sum / sum(poids)) * 5

    if note <= 0 :
        return 0
    elif note >= 5:
        return 5
    else:
        return int(note)
    
def search_info(json_data, ip):
    try:
        as_owner = json_data['data']['attributes']['as_owner']
        #continent = json_data['data']['attributes']['continent']
        country = json_data['data']['attributes']['country']
        timestamp = json_data['data']['attributes']['last_analysis_date']
        whois = json_data['data']['attributes']['whois']
        whois = regex_whois(whois)
        stat_last_analys = json_data['data']['attributes']['last_analysis_stats']
        #adminuslabs_attributes = json_data['data']['attributes']['last_analysis_results']['ADMINUSLabs'] #attribut contenant aussi des attributs plus pronfond
    except KeyError:
        return [ip,"no response from VirusTotalAPI"]
        pass

    print("----------" * 5)
    print("As_owner : ", as_owner)
    print("IP address :", ip)
    print("Dernière analyse : ", timestamp)
    print("Country : ", country)
    print("whois : ", regex_whois(whois))

    #print("ADMINUSLabs attributes:")

    #for key, value in adminuslabs_attributes.items():#je vais venir itérer sur toutes les clés valeur du scaner adminuslabs
    #    print(" ", key + ":", value)
    #print("statistics during the last analysis, which took place on  : ", datetime.fromtimestamp(timestamp) )
    list_scoring = []
    commentaire = ""
    for key, value in stat_last_analys.items():#je vais venir itérer sur tous une un dictionaire
        print(" ", key + ":", value) #les données sont donner dans cette ordre [harmless,malicious,suspicious,timeout,undetected]
        list_scoring.append(value)
        
    if scoring(list_scoring) >= 4:
        commentaire_VT = "VirusTotal Classe Cette IP comme malveillante"
        return [ip,as_owner,country,whois,scoring(list_scoring), commentaire_VT]
    elif scoring(list_scoring) >= 2 < 4: 
        commentaire_VT = "Cette adresse IP est à surveiller"
        return [ip,as_owner,country,whois,scoring(list_scoring), commentaire_VT]
    else:
        return [ip,as_owner,country,whois,scoring(list_scoring), commentaire]
    #return scoring(list_scoring) #je renvoie le score calculer de toutes les infos que j'ai accumuler

if __name__ == "__main__" :
    # PARTIE PREPARATION DES DONNES
    file_info = gui_excel_file() #return a table with 2 information file_path and type_file
    dataframe_excel = open_excel_file(file_info) #renvoie un dataframe du fichier excel

    liste_IP = dataframe_excel["IP"].tolist() #je crée une liste adresse IP a partir de la colonne IP
    liste_domain = dataframe_excel["DOMAIN"].tolist() #je crée une liste adresse Domaine a partir de la colonne Domaine

    réponse = str(input(" 1) IP \n 2) Domain \n 3) test BDD Abuse \n other to quit the program : "))
    tableau_results = []

    if réponse == "1":
        for i in liste_IP:
            data_ip = get_ip_reputation(i) #doit renvoyer toutes les données sur une adresse IP
            tableau_results.append(data_ip) #je crée le tableau qui sera envoyer a ma fonction Print


        print(tableau_results)
        print_to_excel(tableau_results)#envoier mes resultat pour les écrire dans un fichier excel 

        
    elif réponse == "2":
        for i in liste_domain:
            print(i)

    elif réponse == "3":
        path_DB = check_bdd_abuse()
        test = pd.read_csv(path_file_bdd, delimiter=",", names=["Date de signalement","IP","Port de Destination", "Explication"]) #je crée une DataFrame de la BDD Abuse
        print(test)
        test.to_csv("abuse/sslipblacklist.csv")
        print("Comparaison lancer avec Abuse :")
        compare_with_abuse()
    else:
        print("Error Bad comportement")
