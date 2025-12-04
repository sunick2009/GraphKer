import os
import time
import fnmatch
from neo4j import exceptions
from loguru import logger

class CPEInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Configure CPE Files and CPE Cypher Script for insertion
    def cpe_insertion(self):
        logger.info("Inserting CPE Files to Database...")
        files = self.files_to_insert_cpe()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_cpe_script(f)

    # Cypher Query to insert CPE Cypher Script
    def query_cpe_script(self, file):
        start_time = time.time()
        # Insert file with CPE Query Script to Database
        cpes_cypher_file = open(os.path.join(self.import_path, "CPEs.cypher"), "r")
        query = cpes_cypher_file.read()
        query = query.replace('cpeFilesToImport', f"'{file}'")
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

        end_time = time.time()

        logger.info(f"CPE Files: {file} insertion completed within {end_time - start_time}")

    # Define which Dataset and Cypher files will be imported on CPE Insertion
    def files_to_insert_cpe(self):
        target_dir = os.path.join(self.import_path, "nist", "cpe", "splitted")
        if not os.path.exists(target_dir):
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        cpe_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cpe_output"):
                    cpe_files.append(os.path.join("nist", "cpe", "splitted", entry))
                else:
                    continue

        return cpe_files

    # ---------------- Direct ingestion helpers ----------------
    def _load_json(self, rel_path):
        path = os.path.join(self.import_path, rel_path)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _chunked(self, items, size=BATCH_SIZE):
        for i in range(0, len(items), size):
            yield items[i:i+size]

    def direct_insert_cpe(self, direct_limit: int | None = None):
        target_dir = os.path.join(self.import_path, "nist", "cpe", "splitted")
        if not os.path.exists(target_dir):
            logger.warning("No CPE split directory found for direct ingest.")
            return
        files = sorted([f for f in os.listdir(target_dir) if f.startswith("cpe_output") and f.endswith(".json")])
        if not files:
            logger.warning("No CPE files found for direct ingest.")
            return
        cypher = """
        UNWIND $batch AS item
        WITH item WHERE item.cpe23Uri IS NOT NULL
        MERGE (cpe:CPE {uri: item.cpe23Uri})
        FOREACH (child IN coalesce(item.cpe_name, []) |
          MERGE (cchild:CPE {uri: child.cpe23Uri})
          MERGE (cpe)-[:parentOf]->(cchild)
        )
        """
        total = 0
        limit = direct_limit if direct_limit is not None and direct_limit > 0 else None
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CPE files", unit="file"):
                raw = self._load_json(os.path.join("nist", "cpe", "splitted", fname))
                if limit is not None and total >= limit:
                    break
                if limit is not None:
                    remaining = limit - total
                    raw = raw[:remaining]
                total_batches = math.ceil(len(raw) / BATCH_SIZE) if raw else 0
                for batch in tqdm(self._chunked(raw), total=total_batches, leave=False, desc=f"CPE {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
                total += len(raw)
        logger.info(f"CPE direct ingest completed. Inserted items: {total}")
