import json

def load_enterprise_attack(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return json.load(file)

def extract_requested_techniques(enterprise_attack_data, requested_techniques):
    techniques = []
    for technique_id in requested_techniques:
        if technique_id in enterprise_attack_data['techniques']:
            technique = enterprise_attack_data['techniques'][technique_id]
            techniques.append(technique)
    return techniques

def format_as_navigator_json(techniques):
    navigator_json = {
        "techniques": [],
        "gradient": {
            "colors": [],
            "minValue": 0,
            "maxValue": 100
        },
        "legendItems": [],
        "metadata": {
            "name": "MITRE ATT&CK Navigator Layer",
            "version": "1.0",
            "author": "",
            "domain": "mitre-enterprise",
            "description": ""
        }
    }

    for technique in techniques:
        navigator_json['techniques'].append({
            "techniqueID": technique['external_references'][0]['external_id'],
            "color": "#ffffff",  # Colore da definire
            "comment": "",  # Commento da definire
            "enabled": True
        })

    return navigator_json

if __name__ == "__main__":
    file_path = "/home/sy10/mitre_nav/enterprise-attack.json"  # Percorso del file enterprise-attack.json
    requested_techniques = ["T1003", "T1027"]  # Esempio di lista di tecniche richieste dall'utente

    enterprise_attack_data = load_enterprise_attack(file_path)
    requested_techniques_data = extract_requested_techniques(enterprise_attack_data, requested_techniques)
    navigator_json = format_as_navigator_json(requested_techniques_data)

    print(json.dumps(navigator_json, indent=2))
