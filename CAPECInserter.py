import os
import fnmatch
import json
from neo4j import exceptions
from loguru import logger

BATCH_SIZE = 500

class CAPECInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Cypher Query to insert CAPEC refrence Cypher Script
    def query_capec_reference_script(self, file):
        capecs_cypher_file = open(os.path.join(self.import_path, "CAPECs_reference.cypher"), "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecReferenceFilesToImport', f"'{file}'")
        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")

        logger.info(f"CAPEC Files: {file} insertion completed.")

    # Cypher Query to insert CAPEC attack Cypher Script
    def query_capec_attack_script(self, file):
        capecs_cypher_file = open(os.path.join(self.import_path, "CAPECs_attack.cypher"), "r")
        query = capecs_cypher_file.read()

        query = query.replace('capecAttackFilesToImport', f"'{file}'")
        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")


        logger.info(f"CAPEC Files: {file} insertion completed.")

    # Cypher Query to insert CAPEC category Cypher Script
    def query_capec_category_script(self, file):
        capecs_cypher_file = open(os.path.join(self.import_path, "CAPECs_category.cypher"), "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecCategoryFilesToImport', f"'{file}'")

        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")


        logger.info(f"CAPEC Files: {file} insertion completed.")

    # Cypher Query to insert CAPEC view Cypher Script
    def query_capec_view_script(self, file):
        capecs_cypher_file = open(os.path.join(self.import_path, "CAPECs_view.cypher"), "r")
        query = capecs_cypher_file.read()
        query = query.replace('capecViewFilesToImport', f"'{file}'")

        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")


        logger.info(f"CAPEC Files: {file} insertion completed.")

    # Configure CAPEC Files and CAPEC Cypher Script for insertion
    def capec_insertion(self, direct_ingest: bool = False):
        logger.info("Inserting CAPEC Files to Database...")
        if direct_ingest:
            self.direct_insert_references()
            self.direct_insert_attack_patterns()
            self.direct_insert_categories()
            self.direct_insert_views()
            return

        files = self.files_to_insert_capec_reference()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_capec_reference_script(f)

        files = self.files_to_insert_capec_attack()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_capec_attack_script(f)

        files = self.files_to_insert_capec_category()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_capec_category_script(f)

        files = self.files_to_insert_capec_view()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_capec_view_script(f)

    # Define which Dataset and Cypher files will be imported on CAPEC refrence Insertion
    def files_to_insert_capec_reference(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC reference directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        reference_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_reference"):
                    reference_files.append(os.path.join("mitre_capec", "splitted", entry))
                else:
                    continue

        return reference_files

    # Define which Dataset and Cypher files will be imported on CAPEC attack Insertion
    def files_to_insert_capec_attack(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC attack directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        attack_pattern_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_attack_pattern"):
                    attack_pattern_files.append(os.path.join("mitre_capec", "splitted", entry))
                else:
                    continue

        return attack_pattern_files

    # Define which Dataset and Cypher files will be imported on CAPEC category Insertion
    def files_to_insert_capec_category(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC category directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        category_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_category"):
                    category_files.append(os.path.join("mitre_capec", "splitted", entry))
                else:
                    continue

        return category_files

    # Define which Dataset and Cypher files will be imported on CAPEC view Insertion
    def files_to_insert_capec_view(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC view directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        view_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("capec_view"):
                    view_files.append(os.path.join("mitre_capec", "splitted", entry))
                else:
                    continue

        return view_files

    # ---------------- Direct ingestion helpers ----------------
    def _load_json(self, rel_path):
        path = os.path.join(self.import_path, rel_path)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _chunked(self, items, size=BATCH_SIZE):
        for i in range(0, len(items), size):
            yield items[i:i+size]

    def direct_insert_references(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC reference directory missing: {target_dir}")
            return
        files = [f for f in os.listdir(target_dir) if f.startswith("capec_reference") and f.endswith(".json")]
        if not files:
            logger.warning("No CAPEC reference files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS ref
        MERGE (r:External_Reference_ID {Reference_ID: ref.Reference_ID})
          SET r.Author = ref.Author,
              r.Title = ref.Title,
              r.Publication_Year = ref.Publication_Year,
              r.Publication_Month = ref.Publication_Month,
              r.Publisher = ref.Publisher
        """
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CAPEC reference files", unit="file"):
                data = self._load_json(os.path.join("mitre_capec", "splitted", fname))
                total_batches = math.ceil(len(data) / BATCH_SIZE) if data else 0
                for batch in tqdm(self._chunked(data), total=total_batches, leave=False, desc=f"CAPEC ref {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CAPEC references inserted via direct ingest.")

    def direct_insert_attack_patterns(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC attack directory missing: {target_dir}")
            return
        files = [f for f in os.listdir(target_dir) if f.startswith("capec_attack_pattern") and f.endswith(".json")]
        if not files:
            logger.warning("No CAPEC attack pattern files found for direct ingest.")
            return

        def simplify(item):
            rel_w = item.get("Related_Weaknesses", {}).get("Related_Weakness", [])
            if isinstance(rel_w, dict):
                rel_w = [rel_w]
            rel_w_ids = [rw.get("CWE_ID") for rw in rel_w if rw.get("CWE_ID")]
            desc = item.get("Description")
            if isinstance(desc, dict):
                desc = str(desc.get("xhtml:p") or desc)
            return {
                "id": item.get("ID"),
                "name": item.get("Name"),
                "abstraction": item.get("Abstraction"),
                "status": item.get("Status"),
                "description": desc if desc is None or isinstance(desc, str) else str(desc),
                "likelihood": item.get("Likelihood_Of_Attack"),
                "severity": item.get("Typical_Severity"),
                "related_weakness_ids": rel_w_ids,
            }

        cypher = """
        UNWIND $batch AS ap
        WITH ap WHERE ap.id IS NOT NULL
        MERGE (c:CAPEC {Name: 'CAPEC-' + ap.id})
          SET c.Title = ap.name,
              c.Abstraction = ap.abstraction,
              c.Status = ap.status,
              c.Description = ap.description,
              c.Likelihood_Of_Attack = ap.likelihood,
              c.Typical_Severity = ap.severity
        FOREACH (cw IN ap.related_weakness_ids |
          MERGE (w:CWE {Name: 'CWE-' + cw})
          MERGE (c)-[:Related_Weakness]->(w))
        """
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CAPEC attack pattern files", unit="file"):
                raw = self._load_json(os.path.join("mitre_capec", "splitted", fname))
                simplified = [simplify(item) for item in raw]
                total_batches = math.ceil(len(simplified) / BATCH_SIZE) if simplified else 0
                for batch in tqdm(self._chunked(simplified), total=total_batches, leave=False, desc=f"CAPEC attack {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CAPEC attack patterns inserted via direct ingest.")

    def direct_insert_categories(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC category directory missing: {target_dir}")
            return
        files = [f for f in os.listdir(target_dir) if f.startswith("capec_category") and f.endswith(".json")]
        if not files:
            logger.warning("No CAPEC category files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS cat
        WITH cat WHERE cat.id IS NOT NULL
        MERGE (c:CAPEC_CATEGORY {ID: cat.id})
          SET c.Name = cat.name,
              c.Status = cat.status,
              c.Description = cat.description
        """
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CAPEC category files", unit="file"):
                raw = self._load_json(os.path.join("mitre_capec", "splitted", fname))
                simplified = [{"id": i.get("ID"), "name": i.get("Name"), "status": i.get("Status"), "description": i.get("Description")} for i in raw]
                total_batches = math.ceil(len(simplified) / BATCH_SIZE) if simplified else 0
                for batch in tqdm(self._chunked(simplified), total=total_batches, leave=False, desc=f"CAPEC cat {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CAPEC categories inserted via direct ingest.")

    def direct_insert_views(self):
        target_dir = os.path.join(self.import_path, "mitre_capec", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CAPEC view directory missing: {target_dir}")
            return
        files = [f for f in os.listdir(target_dir) if f.startswith("capec_view") and f.endswith(".json")]
        if not files:
            logger.warning("No CAPEC view files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS v
        WITH v WHERE v.id IS NOT NULL
        MERGE (view:CAPEC_VIEW {ID: v.id})
          SET view.Name = v.name,
              view.Status = v.status,
              view.Description = v.description
        """
        with self.driver.session() as session:
            for fname in files:
                raw = self._load_json(os.path.join("mitre_capec", "splitted", fname))
                simplified = [{"id": i.get("ID"), "name": i.get("Name"), "status": i.get("Status"), "description": i.get("Description")} for i in raw]
                for batch in self._chunked(simplified):
                    session.run(cypher, batch=batch)
        logger.info("CAPEC views inserted via direct ingest.")
