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
