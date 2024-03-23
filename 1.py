import re
from pathlib import Path
import json
import requests
import stix2
from typing import Optional, List, Set

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
    # Esempio di utilizzo della classe AttackDB
    attack_db = AttackDB()

    # Esempio di estrazione di una tecnica MITRE ATT&CK
    technique_id = "T1003"
    technique = attack_db.find_technique(technique_id)
    if technique:
        print("Tecnica trovata:")
        print(technique)
    else:
        print(f"Tecnica con ID {technique_id} non trovata.")

