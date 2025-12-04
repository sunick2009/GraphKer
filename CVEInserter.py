import os
import time
import fnmatch
from fileType import FileType
from Util import Util
from neo4j import exceptions
from loguru import logger

class CVEInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Configure CVE Files and CVE Cypher Script for insertion
    def cve_insertion(self):
        logger.info("Inserting CVE Files to Database...")
        files = self.files_to_insert_cve()
        for f in files:
            logger.info(f'Inserting {f}')
            self.query_cve_script(f)

    # Cypher Query to insert CVE Cypher Script
    def query_cve_script(self, file):
        start_time = time.time()
        cves_cypher_file = open(os.path.join(self.import_path, "CVEs.cypher"), "r")
        query = cves_cypher_file.read()
        query = query.replace('cveFilesToImport', f"'{file}'")

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

        logger.info(f"CVE Files: {file} insertion completed within {end_time - start_time}")

    # Define which Dataset and Cypher files will be imported on CVE Insertion
    def files_to_insert_cve(self):
        target_dir = os.path.join(self.import_path, "nist", "cve", "splitted")
        if not os.path.exists(target_dir):
            return []
        listOfFiles = os.listdir(target_dir)
        pattern = "*.json"
        cve_files = []
        for entry in listOfFiles:
            if fnmatch.fnmatch(entry, pattern):
                if entry.startswith("cve_output"):
                    cve_files.append(os.path.join("nist", "cve", "splitted", entry))
                else:
                    continue

        return cve_files

    # ---------------- Direct ingestion helpers ----------------
    def _load_json(self, rel_path):
        path = os.path.join(self.import_path, rel_path)
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _chunked(self, items, size=BATCH_SIZE):
        for i in range(0, len(items), size):
            yield items[i:i+size]

    def direct_insert_cve(self, direct_limit: int | None = None):
        target_dir = os.path.join(self.import_path, "nist", "cve", "splitted")
        if not os.path.exists(target_dir):
            logger.warning("No CVE split directory found for direct ingest.")
            return
        files = sorted([f for f in os.listdir(target_dir) if f.startswith("cve_output") and f.endswith(".json")])
        if not files:
            logger.warning("No CVE files found for direct ingest.")
            return

        cypher = """
        UNWIND $batch AS item
        WITH item WHERE item.cve.CVE_data_meta.ID IS NOT NULL
        MERGE (c:CVE {Name: item.cve.CVE_data_meta.ID})
          SET c.Assigner = item.cve.CVE_data_meta.ASSIGNER,
              c.Description = [d IN item.cve.description.description_data WHERE d.lang = 'en' | d.value],
              c.Published_Date = item.publishedDate,
              c.Last_Modified_Date = item.lastModifiedDate

        FOREACH (pt IN coalesce(item.cve.problemtype.problemtype_data, []) |
          FOREACH (d IN coalesce(pt.description, []) |
            MERGE (w:CWE {Name: d.value})
              SET w.Language = d.lang
            MERGE (c)-[:Problem_Type]->(w)
          )
        )

        FOREACH (cfg IN coalesce(item.configurations.nodes, []) |
          FOREACH (child IN coalesce(cfg.children, []) |
            FOREACH (cm IN coalesce(child.cpe_match, []) |
              MERGE (p:CPE {uri: cm.cpe23Uri})
              MERGE (c)-[:applicableIn {Vulnerable: cm.vulnerable}]->(p)
            )
          )
        )

        FOREACH (ref IN coalesce(item.cve.references.reference_data, []) |
          MERGE (r:Reference_Data {url: ref.url})
            SET r.Name = ref.name, r.refSource = ref.refsource
          MERGE (c)-[:referencedBy]->(r)
        )

        FOREACH (v3 IN CASE WHEN item.impact.baseMetricV3 IS NULL THEN [] ELSE [item.impact.baseMetricV3] END |
          MERGE (cv3:CVSS_3 {Name: item.cve.CVE_data_meta.ID + '_CVSS3'})
          SET cv3 += v3.cvssV3
          MERGE (c)-[:CVSS3_Impact]->(cv3)
        )

        FOREACH (v2 IN CASE WHEN item.impact.baseMetricV2 IS NULL THEN [] ELSE [item.impact.baseMetricV2] END |
          MERGE (cv2:CVSS_2 {Name: item.cve.CVE_data_meta.ID + '_CVSS2'})
          SET cv2 += v2.cvssV2
          MERGE (c)-[:CVSS2_Impact]->(cv2)
        )
        """

        total = 0
        limit = direct_limit if direct_limit is not None and direct_limit > 0 else None
        with self.driver.session() as session:
            for fname in tqdm(files, desc="CVE files", unit="file"):
                raw = self._load_json(os.path.join("nist", "cve", "splitted", fname))
                if limit is not None and total >= limit:
                    break
                if limit is not None:
                    remaining = limit - total
                    raw = raw[:remaining]
                total_batches = math.ceil(len(raw) / BATCH_SIZE) if raw else 0
                for batch in tqdm(self._chunked(raw), total=total_batches, leave=False, desc=f"CVE {fname}", unit="batch"):
                    session.run(cypher, batch=batch)
                total += len(raw)
                if limit is not None and total >= limit:
                    break
        logger.info(f"CVE direct ingest completed. Inserted items: {total}")
