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
