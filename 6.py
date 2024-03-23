import re
from pathlib import Path
import json
import requests
import stix2
from typing import Optional, List, Set, Dict
import argparse

class AttackTechnique:
    def __init__(self, technique: Dict = None) -> None:
        self.technique = technique or {}
        self.name = self.technique.get("name", "Unknown")
        self.tactics = [
            p["phase_name"]
            for p in self.technique.get("kill_chain_phases", [])
            if p["kill_chain_name"] == "mitre-attack"
        ]
        self.platforms = self.technique.get("x_mitre_platforms", [])
        self.data_sources = self.technique.get("x_mitre_data_sources", [])

class AttackDB:
    ATTACK_REGEX = "(T\\d{4}(?:\\.\\d{3})?)"

    def __init__(self, domain: Optional[str] = None, update: bool = False) -> None:
        self.domain: str = domain or "enterprise-attack"
        self.memorystore: stix2.MemoryStore = self._get_cache(self.domain, update)

    def find_technique(self, technique: str) -> stix2.AttackPattern:
        result = self.memorystore.query(
            [stix2.Filter("external_references.external_id", "=", technique)]
        )
        if result:
            return result[0]
        return None

    @staticmethod
    def unique_ids(ids: List[str]) -> Set[str]:
        ids.sort()
        return set([i.strip() for i in ids])

    @staticmethod
    def extract_ids(data: str) -> Set[str]:
        ids = re.findall(AttackDB.ATTACK_REGEX, data)
        return AttackDB.unique_ids(ids)

    @staticmethod
    def _get_cache(
        domain: str = "enterprise-attack", update: bool = False
    ) -> stix2.MemoryStore:
        cache_file = Path(f"{domain}.json").resolve()
        if update or not cache_file.exists():
            stix_json = requests.get(
                f"https://raw.githubusercontent.com/mitre/cti/master/{domain}/{domain}.json"
            ).json()
            cache_file.write_text(json.dumps(stix_json))
        else:
            with open(cache_file, "r") as f:
                stix_json = json.loads(f.read())

        return stix2.MemoryStore(stix_data=stix_json["objects"])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Search for MITRE ATT&CK techniques.")
    parser.add_argument("techniques", metavar="Txxxx", type=str, nargs="+", help="List of MITRE ATT&CK techniques (e.g., T1003 T1027)")
    args = parser.parse_args()

    # Esempio di utilizzo della classe AttackDB
    attack_db = AttackDB()

    techniques_data = []

    count_by_base_id = {}

    for technique_id in args.techniques:
        # Esempio di estrazione di una tecnica MITRE ATT&CK

        technique_data = attack_db.find_technique(technique_id)
        if technique_data:
           technique = AttackTechnique(technique_data)
           techniques_data.append({
                "techniqueID": technique_id,
                "tactic": technique.tactics,
                "enabled": True,
                "comment": "Darktrace",
                "showSubtechniques": False,
                "score": 1 if "." in technique_id else None
            })

           # Logica per calcolare lo score per le tecniche senza sottotecnica
           if "." not in technique_id:
                base_technique_id = technique_id.split(".")[0]  # Estrai il base ID della tecnica
                count_by_base_id[base_technique_id] = count_by_base_id.get(base_technique_id, 0) + 1

    # Assegnazione dello score per le tecniche con sottotecnica
    for base_id, count in count_by_base_id.items():
        for technique in techniques_data:
            if technique["techniqueID"].startswith(base_id):
                technique["score"] = count

    # Caricamento del template del Mitre ATT&CK Navigator
    with open("attack-navigator-template.json", "r") as f:
        navigator_template = json.load(f)

    # Aggiunta delle tecniche estratte al template
    navigator_template["techniques"] = techniques_data

    # Salvataggio dell'output JSON
    with open("output.json", "w") as f:
        json.dump(navigator_template, f, indent=4)

