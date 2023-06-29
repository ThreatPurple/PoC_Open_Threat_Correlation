import json
import re
from datetime import datetime


def regex_whois(texte_whois: str):
    regex = r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}\b"
    resultats = re.search(regex, texte_whois)

    if resultats:
        domaine = resultats.group()
        return domaine
    else:
        return ""
    
def regex_mail(texte_whois: str):
    regex = r"e-mail:\s*([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)"
    resultats = re.search(regex, texte_whois)
    if resultats:
        email = resultats.group(1)
        return email
    else:
        return ""


def print_json_attributes(data, prefix=''):
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = prefix + key + '/'
            if isinstance(value, (dict, list)):
                print_json_attributes(value, new_prefix)
            else:
                print(new_prefix[:-1])
    elif isinstance(data, list):
        for index, item in enumerate(data):
            new_prefix = prefix + str(index) + '/'
            if isinstance(item, (dict, list)):
                print_json_attributes(item, new_prefix)
            else:
                print(new_prefix[:-1])

def search_info(json_data):
    as_owner = json_data['data']['attributes']['as_owner']
    continent = json_data['data']['attributes']['continent']
    country = json_data['data']['attributes']['country']
    timestamp = json_data['data']['attributes']['last_analysis_date']
    whois = json_data['data']['attributes']['whois']
    stat_last_analys = json_data['data']['attributes']['last_analysis_stats']
    #adminuslabs_attributes = json_data['data']['attributes']['last_analysis_results']['ADMINUSLabs'] #attribut contenant aussi des attributs plus pronfond

    print("as_owner:", as_owner)
    print("continent:", continent)
    print("country:", country)
    print("DNS Owner : ", regex_whois(whois))
    print("contact the domain owner :  ", regex_mail(whois))

    #print("ADMINUSLabs attributes:")

    #for key, value in adminuslabs_attributes.items():#je vais venir itérer sur toutes les clés valeur du scaner adminuslabs
    #    print(" ", key + ":", value)
    print("statistics during the last analysis, which took place on  : ", datetime.fromtimestamp(timestamp) )
    list_scoring = []

    for key, value in stat_last_analys.items():#je vais venir itérer sur tous une un dictionaire
        print(" ", key + ":", value) #les données sont donner dans cette ordre [harmless,malicious,suspicious,timeout,undetected]
        list_scoring.append(value)
    #print([as_owner,continent,country,scoring(list_scoring)])
    return [as_owner,continent,country,scoring(list_scoring)]
    #return scoring(list_scoring) #je renvoie le score calculer de toutes les infos que j'ai accumuler
    


def scoring(scoring_list): #algorithme de pondération des différentes notes 
    weight_harmless =  -0.25 # par scanner qui le détecte comme innofensif le score baise de 25%
    weight_malicious = 1 #par scanner qui le détecte comme malicieux le score baise de 100%
    weight_suspicious = 0.4 #par scanner qui le détecte comme suspicieux le score baise de 40%
    weight_undetected = 0 #je ne prend pas en compte les undected
    #je définis les poids pour chaque élément
    poids = [-0.25,1.2,0.4,0]

    ponderation_sum = sum([scoring_list[i] * poids[i] for i in range(4)])
    note = (ponderation_sum / sum(poids)) * 5

    if note < 0 :
        return 0
    else:
        return int(note) 

def main():
    try:
        choix = str(input(" 1) fichier test json \n 2) fichier Bad IP \n : "))
    except TypeError:
        print("Erreur vous n'avez choisie aucune option")
        exit()

    if choix == "1" or "2":
        if choix == "1":
            file = "test.json"
        elif choix == "2":
            file = "reponse_bad_ip.json"
    else:
        exit()
    with open(file, "r") as file:
        json_file = json.load(file)#contenue charcher au format json

    #print(data)
    print_json_attributes(data=json_file)
    print("-------------" * 4)
    aucun = search_info(json_file)
    print(aucun)
if __name__ == "__main__" :
    main()