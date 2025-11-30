import argparse
import os
import webbrowser
from neo4j import GraphDatabase
import scraper
import time
from loguru import logger
from Util import Util
from CPEInserter import CPEInserter
from CWEInserter import CWEInserter
from CVEInserter import CVEInserter
from CAPECInserter import CAPECInserter
from DatabaseUtil import DatabaseUtil
from nvd_downloader import NVDSourceConfig

# Define the functions that will be running
def run(url_db, username, password, directory, neo4jbrowser, graphlytic,
        nvd_source: str | None = None, nvd_api_key: str | None = None,
        nvd_years: str | None = None, reuse_downloads: bool = False,
        skip_cpe: bool = False, direct_ingest: bool = False, skip_cve: bool = False):
    driver = None
    try:
        # Fail fast if Neo4j is unreachable to avoid doing heavy downloads first.
        connection_driver = GraphDatabase.driver(url_db, auth=(username, password))
        try:
            connection_driver.verify_connectivity()
            logger.info(f"Connected to Neo4j at {url_db}")
        finally:
            connection_driver.close()

        start_time = time.time()

        import_path = Util.set_import_path(directory)

        nvd_config = NVDSourceConfig.from_env()
        if nvd_source:
            nvd_config.source = nvd_source
        if nvd_api_key:
            nvd_config.api_key = nvd_api_key
        if nvd_years:
            if nvd_years.strip().lower() == "all":
                current_year = time.gmtime().tm_year
                nvd_config.years = list(range(1999, current_year + 1))
            else:
                nvd_config.years = [int(year) for year in nvd_years.split(',') if year.strip().isdigit()]

        if reuse_downloads:
            logger.info("Reusing existing downloaded datasets (skipping clear/download).")
        else:
            Util.clear_directory(import_path)
            scraper.download_datasets(import_path, nvd_config, skip_cpe=skip_cpe)

        Util.copy_files_cypher_script(import_path)

        driver = GraphDatabase.driver(url_db, auth=(username, password))

        cpeInserter = CPEInserter(driver, import_path)
        cveInserter = CVEInserter(driver, import_path)
        cweInserter = CWEInserter(driver, import_path)
        capecInserter = CAPECInserter(driver, import_path)
        databaseUtil = DatabaseUtil(driver)

        databaseUtil.clear()
        databaseUtil.schema_script()
        if not skip_cpe:
            cpeInserter.cpe_insertion()
        capecInserter.capec_insertion(direct_ingest=direct_ingest)
        if not skip_cve:
            cveInserter.cve_insertion()
        cweInserter.cwe_insertion(direct_ingest=direct_ingest)

        driver.close()

        end_time = time.time()

        execution_time = end_time - start_time
        logger.info(f"Import finished in: {execution_time:.6f} seconds")

    except Exception as e:
        logger.exception(f"Error occurred: {e}")
        if driver:
            driver.close()

    if neo4jbrowser:
        webbrowser.open("http://localhost:7474")
    if graphlytic:
        webbrowser.open("http://localhost:8110/")
    return


def main():
    Util.load_env_file()
    Util.setup_logger()
    # Initialize the parser
    parser = argparse.ArgumentParser(
        description=" +-+-+-+-+-+-+-+-+ \n |G|r|a|p|h|K|e|r| \n +-+-+-+-+-+-+-+-+"
                    "\n \nWith GraphKer you can have the most recent update of cyber-security vulnerabilities, weaknesses, attack patterns and platforms "
                    "from MITRE and NIST, in an very useful and user friendly way provided by neo4j graph databases! \n \n"
                    "--Search, Export Data and Analytics, Enrich your Skills-- \n \n"
                    "**Created by Adamantios - Marios Berzovitis, Cybersecurity Expert MSc, BSc** \n"
                    "Diploma Research - MSc @ Distributed Systems, Security and Emerging Information Technologies | University Of Piraeus \n"
                    "Co-Working with Cyber Security Research Lab | University Of Piraeus \n"
                    "LinkedIn:https://tinyurl.com/p57w4ntu \n"
                    "Github:https://github.com/amberzovitis \n \n"
                    "Enjoy! Provide Feedback!", formatter_class=argparse.RawTextHelpFormatter
    )

    # Add Parameters
    parser.add_argument('-u', '--urldb', required=True,
                        help="Insert bolt url of your neo4j graph database.")
    parser.add_argument('-n', '--username', required=True,
                        help="Insert username of your graph database.")
    parser.add_argument('-p', '--password', required=True,
                        help="Insert password of your graph database.")
    parser.add_argument('-d', '--directory', required=True,
                        help="Insert import path of your graph database.")
    parser.add_argument('-b', '--neo4jbrowser', choices=['y', 'Y'],
                        help="Press y or Y to open neo4jbrowser after the insertion of elements in your graph database.")
    parser.add_argument('-g', '--graphlytic', choices=['y', 'Y'],
                        help="Press y or Y to open Graphlytic app after the insertion of elements in your graph database.")
    parser.add_argument('--nvd-source', choices=['mirror', 'api'],
                        default=os.getenv('NVD_SOURCE', 'mirror'),
                        help="Select NVD data source. Default is mirror (FKIE-CAD GitHub feeds).")
    parser.add_argument('--nvd-api-key', default=os.getenv('NVD_API_KEY'),
                        help="NVD 2.0 API key used when --nvd-source=api or when environment requires it.")
    parser.add_argument('--nvd-years', default=os.getenv('NVD_YEARS'),
                        help="Comma separated years to fetch from mirror/API (e.g. 2023,2024) or 'all'. Defaults to recent feeds only.")
    parser.add_argument('--reuse-downloads', action='store_true',
                        help="Reuse existing downloaded datasets in the import directory (skip clearing and re-downloading).")
    parser.add_argument('--skip-cpe', action='store_true',
                        help="Skip CPE download and insertion (useful when API key/rate limits are problematic).")
    parser.add_argument('--direct-ingest', action='store_true',
                        help="Insert datasets directly via driver (no apoc.load.json/file import) for supported types (currently CWE/CAPEC).")
    parser.add_argument('--skip-cve', action='store_true',
                        help="Skip CVE insertion (useful when Neo4j cannot read local import files).")

    args = parser.parse_args()
    if args.neo4jbrowser == "y" or args.neo4jbrowser == "Y":
        neo4jbrowser_open = True
    else:
        neo4jbrowser_open = False
    if args.graphlytic == "y" or args.neo4jbrowser == "Y":
        graphlytic_open = True
    else:
        graphlytic_open = False
    run(args.urldb, args.username, args.password,
        args.directory, neo4jbrowser_open, graphlytic_open,
        nvd_source=args.nvd_source, nvd_api_key=args.nvd_api_key,
        nvd_years=args.nvd_years, reuse_downloads=args.reuse_downloads,
        skip_cpe=args.skip_cpe, direct_ingest=args.direct_ingest,
        skip_cve=args.skip_cve)
    return


if __name__ == '__main__':
    main()
