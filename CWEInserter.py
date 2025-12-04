import os
import fnmatch
import json
import math
from neo4j import exceptions
from loguru import logger
from tqdm import tqdm

BATCH_SIZE = 500

class CWEInserter:

    def __init__(self, driver, import_path, apoc_import_path):
        self.driver = driver
        self.import_path = import_path          # local path to list files
        self.apoc_import_path = apoc_import_path  # path visible to Neo4j for file:///

    def _log_apoc_summary(self, records, label, file_url):
        if not records:
            logger.warning(f"{label} {file_url} returned no summary rows from apoc.")
            return
        r = records[0]
        parts = []
        for k in ["batches", "total", "committedOperations", "failedOperations", "failedBatches", "timeTaken"]:
            if k in r:
                parts.append(f"{k}={r[k]}")
        logger.info(f"{label} {file_url} summary: " + ", ".join(parts) if parts else f"{label} {file_url} summary: {r}")

    # Cypher Query to insert CWE reference Cypher Script
    def query_cwe_reference_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_reference.cypher"), "r")
        query = cwes_cypher_file.read()
        apoc_path = os.path.join(self.apoc_import_path, file)
        file_url = f"file:///{apoc_path.replace(os.sep, '/')}"

        try:
            with self.driver.session() as session:
                result = session.run(query, cweReferenceFilesToImport=[file_url])
                self._log_apoc_summary(result.data(), "CWE reference", file_url)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")

        logger.info(f"CWE Files: {file} insertion completed.")

    # Cypher Query to insert CWE weakness Cypher Script
    def query_cwe_weakness_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_weakness.cypher"), "r")
        query = cwes_cypher_file.read()
        apoc_path = os.path.join(self.apoc_import_path, file)
        file_url = f"file:///{apoc_path.replace(os.sep, '/')}"

        try:
            with self.driver.session() as session:
                result = session.run(query, cweWeaknessFilesToImport=[file_url])
                self._log_apoc_summary(result.data(), "CWE weakness", file_url)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")

        logger.info(f"CWE Files: {file} insertion completed.")

    # Cypher Query to insert CWE category Cypher Script
    def query_cwe_category_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_category.cypher"), "r")
        query = cwes_cypher_file.read()
        apoc_path = os.path.join(self.apoc_import_path, file)
        file_url = f"file:///{apoc_path.replace(os.sep, '/')}"

        try:
            with self.driver.session() as session:
                result = session.run(query, cweCategoryFilesToImport=[file_url])
                self._log_apoc_summary(result.data(), "CWE category", file_url)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")

        logger.info(f"CWE Files: {file} insertion completed.")

    # Cypher Query to insert CWE view Cypher Script
    def query_cwe_view_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_view.cypher"), "r")
        query = cwes_cypher_file.read()
        apoc_path = os.path.join(self.apoc_import_path, file)
        file_url = f"file:///{apoc_path.replace(os.sep, '/')}"

        try:
            with self.driver.session() as session:
                result = session.run(query, cweViewFilesToImport=[file_url])
                self._log_apoc_summary(result.data(), "CWE view", file_url)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        except exceptions.DriverError as e:
            logger.error(f"DriverError: {e}")
        except Exception as e:
            # Handle other exceptions
            logger.exception(f"An error occurred: {e}")

        logger.info(f"CWE Files: {file} insertion completed.")

    # Configure CWE Files and CWE Cypher Script for insertion
    def cwe_insertion(self, direct_ingest: bool = False):
        logger.info("Inserting CWE Files to Database...")
        if direct_ingest:
            self.direct_insert_references()
            self.direct_insert_weaknesses()
            self.direct_insert_categories()
            self.direct_insert_views()
            return

        files = self.files_to_insert_cwe_reference()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_cwe_reference_script(f)

        files = self.files_to_insert_cwe_weakness()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_cwe_weakness_script(f)

        files = self.files_to_insert_cwe_category()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_cwe_category_script(f)

        files = self.files_to_insert_cwe_view()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_cwe_view_script(f)

    # Define which Dataset and Cypher files will be imported on CWE reference Insertion
    def files_to_insert_cwe_reference(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CWE reference directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"

        reference_files = []

        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_reference"):
                    reference_files.append(os.path.join("mitre_cwe", "splitted", entry))
                else:
                    continue

        return reference_files

    # Define which Dataset and Cypher files will be imported on CWE weakness Insertion
    def files_to_insert_cwe_weakness(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CWE weakness directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        weakness_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_weakness"):
                    weakness_files.append(os.path.join("mitre_cwe", "splitted", entry))
                else:
                    continue

        return weakness_files


    # Define which Dataset and Cypher files will be imported on CWE category Insertion
    def files_to_insert_cwe_category(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CWE category directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        category_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_category"):
                    category_files.append(os.path.join("mitre_cwe", "splitted", entry))
                else:
                    continue

        return category_files


    # Define which Dataset and Cypher files will be imported on CWE view Insertion
    def files_to_insert_cwe_view(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        if not os.path.exists(target_dir):
            logger.warning(f"CWE view directory missing: {target_dir}")
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        view_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cwe_view"):
                    view_files.append(os.path.join("mitre_cwe", "splitted", entry))
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
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        files = [f for f in os.listdir(target_dir) if f.startswith("cwe_reference") and f.endswith(".json")]
        if not files:
            logger.warning("No CWE reference files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS ref
        MERGE (r:External_Reference_CWE {Reference_ID: ref.Reference_ID})
          SET r.Author = ref.Author,
              r.Title = ref.Title,
              r.Edition = ref.Edition,
              r.URL = ref.URL,
              r.Publication_Year = ref.Publication_Year,
              r.Publisher = ref.Publisher
        """
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CWE reference files", unit="file"):
                data = self._load_json(os.path.join("mitre_cwe", "splitted", fname))
                total_batches = math.ceil(len(data) / BATCH_SIZE) if data else 0
                for batch in tqdm(self._chunked(data), total=total_batches, leave=False, desc=f"CWE ref {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CWE references inserted via direct ingest.")

    def direct_insert_weaknesses(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        files = [f for f in os.listdir(target_dir) if f.startswith("cwe_weakness") and f.endswith(".json")]
        if not files:
            logger.warning("No CWE weakness files found for direct ingest.")
            return

        def simplify(item):
            related = item.get("Related_Weaknesses", {}).get("Related_Weakness", [])
            if isinstance(related, dict):
                related = [related]
            rel_ids = [rw.get("CWE_ID") for rw in related if rw.get("CWE_ID")]

            rel_capec = item.get("Related_Attack_Patterns", {}).get("Related_Attack_Pattern", [])
            if isinstance(rel_capec, dict):
                rel_capec = [rel_capec]
            rel_capec_ids = [rc.get("CAPEC_ID") for rc in rel_capec if rc.get("CAPEC_ID")]

            refs = item.get("References", {}).get("Reference", [])
            if isinstance(refs, dict):
                refs = [refs]
            ref_ids = [r.get("External_Reference_ID") for r in refs if r.get("External_Reference_ID")]

            return {
                "id": item.get("ID"),
                "name": item.get("Name"),
                "abstraction": item.get("Abstraction"),
                "structure": item.get("Structure"),
                "status": item.get("Status"),
                "description": item.get("Description"),
                "related_weakness_ids": rel_ids,
                "related_capec_ids": rel_capec_ids,
                "reference_ids": ref_ids,
            }

        cypher = """
        UNWIND $batch AS w
        WITH w WHERE w.id IS NOT NULL
        MERGE (c:CWE {Name: 'CWE-' + w.id})
          SET c.Extended_Name = w.name,
              c.Abstraction = w.abstraction,
              c.Structure = w.structure,
              c.Status = w.status,
              c.Description = w.description
        FOREACH (rid IN w.reference_ids |
          MERGE (r:External_Reference_CWE {Reference_ID: rid})
          MERGE (c)-[:hasExternal_Reference]->(r))
        FOREACH (rw IN w.related_weakness_ids |
          MERGE (cw:CWE {Name: 'CWE-' + rw})
          MERGE (c)-[:Related_Weakness]->(cw))
        FOREACH (cap IN w.related_capec_ids |
          MERGE (cp:CAPEC {Name: 'CAPEC-' + cap})
          MERGE (c)-[:RelatedAttackPattern]->(cp))
        """

        with self.driver.session() as session:
            for fname in tqdm(files, desc="CWE weakness files", unit="file"):
                raw = self._load_json(os.path.join("mitre_cwe", "splitted", fname))
                simplified = [simplify(item) for item in raw]
                total_batches = math.ceil(len(simplified) / BATCH_SIZE) if simplified else 0
                for batch in tqdm(self._chunked(simplified), total=total_batches, leave=False, desc=f"CWE weak {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CWE weaknesses inserted via direct ingest.")

    def direct_insert_categories(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        files = [f for f in os.listdir(target_dir) if f.startswith("cwe_category") and f.endswith(".json")]
        if not files:
            logger.warning("No CWE category files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS cat
        WITH cat WHERE cat.id IS NOT NULL
        MERGE (c:CWE_CATEGORY {ID: cat.id})
          SET c.Name = cat.name,
              c.Status = cat.status,
              c.Summary = cat.summary
        """
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CWE category files", unit="file"):
                raw = self._load_json(os.path.join("mitre_cwe", "splitted", fname))
                simplified = [{"id": i.get("ID"), "name": i.get("Name"), "status": i.get("Status"), "summary": i.get("Summary")} for i in raw]
                total_batches = math.ceil(len(simplified) / BATCH_SIZE) if simplified else 0
                for batch in tqdm(self._chunked(simplified), total=total_batches, leave=False, desc=f"CWE cat {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CWE categories inserted via direct ingest.")

    def direct_insert_views(self):
        target_dir = os.path.join(self.import_path, "mitre_cwe", "splitted")
        files = [f for f in os.listdir(target_dir) if f.startswith("cwe_view") and f.endswith(".json")]
        if not files:
            logger.warning("No CWE view files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS v
        WITH v WHERE v.id IS NOT NULL
        MERGE (view:CWE_VIEW {ID: v.id})
          SET view.Name = v.name,
              view.Type = v.type,
              view.Status = v.status,
              view.Objective = v.objective
        """
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CWE view files", unit="file"):
                raw = self._load_json(os.path.join("mitre_cwe", "splitted", fname))
                simplified = []
                for i in raw:
                    obj = i.get("Objective")
                    if isinstance(obj, dict):
                        obj = str(obj.get("xhtml:p") or obj)
                    simplified.append({
                        "id": i.get("ID"),
                        "name": i.get("Name"),
                        "type": i.get("Type"),
                        "status": i.get("Status"),
                        "objective": obj if obj is None or isinstance(obj, str) else str(obj),
                    })
                total_batches = math.ceil(len(simplified) / BATCH_SIZE) if simplified else 0
                for batch in tqdm(self._chunked(simplified), total=total_batches, leave=False, desc=f"CWE view {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
        logger.info("CWE views inserted via direct ingest.")
