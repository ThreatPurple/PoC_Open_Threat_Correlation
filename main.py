import requests
from tkinter import filedialog 
from tkinter import *
import pathlib
import sys
import pandas as pd
#import json
import re
#from datetime import datetime
from openpyxl import Workbook
from openpyxl.styles import PatternFill #pour colorier le DataFram
from openpyxl.utils.dataframe import dataframe_to_rows

#installer le module xlrd pour prendre en charche les fichier exel
api_key_VT = "Please enter your VT API key here" #si vous n'avez pas abonnements PRO il faudra Timer et mettre une pasue toutes les 4 minutes après avoir scanner 5 URL

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
    df = pd.read_excel("Output_Script.xlsx")
    try:
        if x < 2:
            return "background-color: lightgreen"
        elif 2 <= x <=3 :
            return "background-color: yellow"
        elif x > 3:
            return "background-color: red"
    except TypeError:
        pass
        

def print_to_excel(json_data: list):
    df = pd.DataFrame(data=json_data, columns=["IP", "AS Owner", "Continent", "Country","DNS Owner", "Score"]) #ci je produit et ordre ma DataFrame
    print(df)
    style_dataframe = df.style.applymap(color_cell) #je colorise mets case en focntion de mes critére

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
    "x-apikey": api_key
    }
    response = requests.get(url, headers=headers_VT_domain_reputation)
    response = response.json()
    return response

def get_ip_reputation(ip_addres: str):
    url = "https://www.virustotal.com/api/v3/ip_addresses/{}".format(ip_addres)
    headers_VT_ip_reputation = {
    "accept": "application/json",
    "x-apikey": api_key
    }
    response = requests.get(url, headers=headers_VT_ip_reputation)
    response_json = response.json()#je recupere la réponse du serveur en version JSON
    response_data = search_info(response_json, ip_addres) #je vais chercher les informations que je desire dans ma réponse json
    return response_data

def scoring(scoring_list): #algorithme de pondération des différentes notes 
    weight_harmless =  -0.25 # par scanner qui le détecte comme innofensif le score baise de 25%
    weight_malicious = 1 #par scanner qui le détecte comme malicieux le score baise de 100%
    weight_suspicious = 0.4 #par scanner qui le détecte comme suspicieux le score baise de 40%
    weight_undetected = 0.5 #les scanner ne connaissent pas cette adresse IP
    #je définis les poids pour chaque élément
    poids = [-0.25,3,0.4,0.5]

    ponderation_sum = sum([scoring_list[i] * poids[i] for i in range(4)])
    note = (ponderation_sum / sum(poids)) * 5

    if note < 0 :
        return 0
    elif note > 5:
        return 5
    else:
        return int(note) 
    
def search_info(json_data, ip):
    try:
        as_owner = json_data['data']['attributes']['as_owner']
        continent = json_data['data']['attributes']['continent']
        country = json_data['data']['attributes']['country']
        #timestamp = json_data['data']['attributes']['last_analysis_date']
        whois = json_data['data']['attributes']['whois']
        whois = regex_whois(whois)
        stat_last_analys = json_data['data']['attributes']['last_analysis_stats']
        #adminuslabs_attributes = json_data['data']['attributes']['last_analysis_results']['ADMINUSLabs'] #attribut contenant aussi des attributs plus pronfond
    except KeyError:
        return [ip,"no response from VirusTotalAPI"]
        pass

    print("----------" * 5)
    print("as_owner : ", as_owner)
    print("IP address :", ip)
    print("continent : ", continent)
    print("country : ", country)
    print("whois : ", regex_whois(whois))

    #print("ADMINUSLabs attributes:")

    #for key, value in adminuslabs_attributes.items():#je vais venir itérer sur toutes les clés valeur du scaner adminuslabs
    #    print(" ", key + ":", value)
    #print("statistics during the last analysis, which took place on  : ", datetime.fromtimestamp(timestamp) )
    list_scoring = []

    for key, value in stat_last_analys.items():#je vais venir itérer sur tous une un dictionaire
        print(" ", key + ":", value) #les données sont donner dans cette ordre [harmless,malicious,suspicious,timeout,undetected]
        list_scoring.append(value)
    #print([as_owner,continent,country,scoring(list_scoring)])
    return [ip,as_owner,continent,country,whois,scoring(list_scoring)]
    #return scoring(list_scoring) #je renvoie le score calculer de toutes les infos que j'ai accumuler

if __name__ == "__main__" :
    # PARTIE PREPARATION DES DONNES
    file_info = gui_excel_file() #return a table with 2 information file_path and type_file
    dataframe_excel = open_excel_file(file_info) #renvoie un dataframe du fichier excel

    liste_IP = dataframe_excel["IP"].tolist() #je crée une liste adresse IP a partir de la colonne IP
    liste_domain = dataframe_excel["DOMAIN"].tolist() #je crée une liste adresse Domaine a partir de la colonne Domaine

    réponse = str(input(" 1) IP \n 2) Domain \n 3) Print Infos \n other to quit the program : "))
    #liste_choisie = choice(réponse)
    #PARTIE ENVOIE DES DONNEES
    tableau_results = []
    if réponse == "1":
        for i in liste_IP:
            data_ip = get_ip_reputation(i) #doit renvoyer toutes les données sur une adresse IP
            tableau_results.append(data_ip)
        print(tableau_results)
        print_to_excel(tableau_results)#envoier mes resultat pour les écrire dans un fichier excel 
    elif réponse == "2":
        for i in liste_domain:
            print(i)
    else:
        print("Error Bad comportement")
