import os
import fnmatch
from neo4j import exceptions
from loguru import logger

class CWEInserter:

    def __init__(self, driver, import_path):
        self.driver = driver
        self.import_path = import_path

    # Cypher Query to insert CWE reference Cypher Script
    def query_cwe_reference_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_reference.cypher"), "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweReferenceFilesToImport', f"'{file}'")

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

        logger.info(f"CWE Files: {file} insertion completed.")

    # Cypher Query to insert CWE weakness Cypher Script
    def query_cwe_weakness_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_weakness.cypher"), "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweWeaknessFilesToImport', f"'{file}'")

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

        logger.info(f"CWE Files: {file} insertion completed.")

    # Cypher Query to insert CWE category Cypher Script
    def query_cwe_category_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_category.cypher"), "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweCategoryFilesToImport', f"'{file}'")

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

        logger.info(f"CWE Files: {file} insertion completed.")

    # Cypher Query to insert CWE view Cypher Script
    def query_cwe_view_script(self, file):
        cwes_cypher_file = open(os.path.join(self.import_path, "CWEs_view.cypher"), "r")
        query = cwes_cypher_file.read()
        query = query.replace('cweViewFilesToImport', f"'{file}'")

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

        logger.info(f"CWE Files: {file} insertion completed.")

    # Configure CWE Files and CWE Cypher Script for insertion
    def cwe_insertion(self):
        logger.info("Inserting CWE Files to Database...")
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
