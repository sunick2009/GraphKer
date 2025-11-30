import time
from neo4j import exceptions
from loguru import logger

class DatabaseUtil:

    def __init__(self, driver):
        self.driver = driver

    # Clear Database
    def clear(self):
        # Clear Database from existing nodes and relationships
        start_time = time.time()
        logger.info("Start cleaning data from existing nodes and relationships")
        labels = ["CPE", "CVE", "CVSS_2", "CVSS_3", "Reference_Data", "CWE", "Detection_Method", "Demonstrative_Example", "External_Reference_CWE", "CWE_VIEW", "Stakeholder", "Applicable_Platform", "Mitigation", "Consequence", "CAPEC", "External_Reference_ID", "CAPEC_VIEW"]
        for label in labels:
            logger.info(f"Deleting {label}")
            query = "CALL apoc.periodic.iterate('MATCH (n:" + label + ") RETURN n', 'DETACH DELETE n', {batchSize:2000})"
            try:
                with self.driver.session() as session:
                    session.run(query)
            except exceptions.CypherError as e:
                logger.error(f"CypherError: {e}")
            logger.info(f"{label} deleted successfully")

        end_time = time.time()

        logger.info(f"Previous data have been deleted within {end_time - start_time}")

        self.clearSchema()
        logger.info("Database is clear and ready for imports.")

    # Clear Schema
    def clearSchema(self):
        # Clear Database from existing constraints and indexes
        logger.info("Start cleaning data from existing constraints and indexes")
        start_time = time.time()
        query = """CALL apoc.cypher.runSchemaFile("ClearConstraintsIndexes.cypher")"""
        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        end_time = time.time()
        logger.info(f"Previous schema has been deleted {end_time - start_time}")

    # Constraints and Indexes
    def schema_script(self):
        # Create Constraints and Indexes
        logger.info("Start creating constraints and indexes")
        start_time = time.time()
        query = """CALL apoc.cypher.runSchemaFile("ConstraintsIndexes.cypher")"""
        try:
            with self.driver.session() as session:
                session.run(query)
        except exceptions.CypherError as e:
            logger.error(f"CypherError: {e}")
        end_time = time.time()
        logger.info(f"Schema with constraints and indexes insertion completed {end_time - start_time}")
