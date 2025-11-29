import os
import platform
import zipfile
import json
import xmltodict
import fnmatch
import subprocess

import requests
from bs4 import BeautifulSoup
from circuitbreaker import circuit

from nvd_downloader import (
    NVDMirrorClient,
    NVDApiClient,
    NVDSourceConfig,
    write_cpe_batches,
    write_cve_batches,
)


MAX_RETRIES = 5

def download_files_cve(import_path, nvd_config: NVDSourceConfig | None = None):
    """Download CVE data using the configured NVD source.

    The mirror mode (default) uses the FKIE-CAD GitHub releases and works
    without authentication. API mode relies on the official NVD 2.0 API
    and the optional ``NVD_API_KEY``.
    """

    config = nvd_config or NVDSourceConfig.from_env()
    cve_output_dir = os.path.join(import_path, "nist", "cve")
    os.makedirs(cve_output_dir, exist_ok=True)

    print('\nUpdating the Database with the latest CVE Files...')
    if config.source == "mirror":
        client = NVDMirrorClient()
        cve_items = client.iter_cve_items(years=config.years)
    else:
        client = NVDApiClient(config.api_key)
        cve_items = client.iter_cve_items()

    write_cve_batches(cve_items, cve_output_dir)

def download_files_cpe(import_path, nvd_config: NVDSourceConfig | None = None):
    """Download CPE data from the NVD API.

    CPE feeds are no longer mirrored; when no API key is provided the
    function exits gracefully so that CVE processing can continue.
    """

    config = nvd_config or NVDSourceConfig.from_env()
    if config.source != "api":
        print("\nCPE mirror feeds are unavailable. Provide NVD_API_KEY and set NVD_SOURCE=api to import CPE data.")
        return

    cpe_output_dir = os.path.join(import_path, "nist", "cpe")
    os.makedirs(cpe_output_dir, exist_ok=True)

    if not config.api_key:
        print("\nNVD_API_KEY not provided; skipping CPE download.")
        return

    print('\nUpdating the Database with the latest CPE Files via NVD API...')
    client = NVDApiClient(config.api_key)
    write_cpe_batches(client.iter_cpe_items(), cpe_output_dir)

def download_files_cwe(import_path):
    url = 'https://cwe.mitre.org/data/archive.html'
    root = 'https://cwe.mitre.org/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    zip_files = [
        dl for dl in all_links if dl and '.xml.zip' in dl
    ]
    zip_file = zip_files[0]
    download_folder = import_path + "mitre_cwe/"
    extract_dir = import_path + "mitre_cwe/"

    # Download and Unzip the files
    print('\nUpdating the Database with the latest CWE Files...')
    full_url = root + zip_file
    zip_file_name = os.path.basename(zip_file)

    # 5 attempts to download and unzip the file correctly
    download_file_to_path(full_url, download_folder, zip_file_name)
    unzip_files_to_directory(download_folder, extract_dir, zip_file_name)
    transform_xml_files_to_json(extract_dir)
    replace_unwanted_string_cwe(extract_dir)
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cwe_reference','Weakness_Catalog.External_References.External_Reference')
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cwe_weakness','Weakness_Catalog.Weaknesses.Weakness')
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cwe_category','Weakness_Catalog.Categories.Category')
    transform_big_json_files_to_multiple_json_files(extract_dir, 'cwe_view','Weakness_Catalog.Views.View')

def download_files_capec(import_path):
    url = 'https://capec.mitre.org/data/archive.html'
    root = 'https://capec.mitre.org/'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    all_hrfs = soup.find_all('a')
    all_links = [
        link.get('href') for link in all_hrfs
    ]
    xml_files = [
        dl for dl in all_links if dl and '.xml' in dl
    ]
    xml_file = xml_files[0]

    download_folder = import_path + "mitre_capec/"
    extract_dir = import_path + "mitre_capec/"

    # Download xml file
    print('\nUpdating the Database with the latest CAPEC Files...')
    full_url = root + xml_file
    zip_file_name = os.path.basename(xml_file)

    download_file_to_path(full_url, download_folder, zip_file_name)
    current_os = platform.system()
    if (current_os == "Linux" or current_os == "Darwin"):
        run_dos2unix(os.path.join(download_folder, zip_file_name))
    transform_xml_files_to_json(download_folder)
    replace_unwanted_string_capec(download_folder)
    transform_big_json_files_to_multiple_json_files(extract_dir, 'capec_reference','Attack_Pattern_Catalog.External_References.External_Reference')
    transform_big_json_files_to_multiple_json_files(extract_dir, 'capec_attack_pattern','Attack_Pattern_Catalog.Attack_Patterns.Attack_Pattern')
    transform_big_json_files_to_multiple_json_files(extract_dir, 'capec_category','Attack_Pattern_Catalog.Categories.Category')
    transform_big_json_files_to_multiple_json_files(extract_dir, 'capec_view','Attack_Pattern_Catalog.Views.View')


def download_datasets(import_path, nvd_config: NVDSourceConfig | None = None):
    config = nvd_config or NVDSourceConfig.from_env()
    download_files_cve(import_path, config)
    download_files_cpe(import_path, config)
    download_files_cwe(import_path)
    download_files_capec(import_path)

# Define the function that makes the HTTP request with retry
def make_http_request_with_retry(url, retries=0):
    try:
        # Call the function that makes the HTTP request, protected by the circuit breaker
        return download_file_to_path(url)
    except circuit.BreakerOpenError:
        if retries < MAX_RETRIES:
            print(f"Circuit is open. Retrying... Attempt {retries + 1}")
            return make_http_request_with_retry(url, retries=retries + 1)
        else:
            raise RuntimeError("Circuit is open. Max retries reached.")
    except Exception as e:
        if retries < MAX_RETRIES:
            print(f"Error occurred: {e}. Retrying... Attempt {retries + 1}")
            return make_http_request_with_retry(url, retries=retries + 1)
        else:
            raise RuntimeError("Max retries reached. Last error: {}".format(e))

# Define the function that makes the HTTP request
@circuit(failure_threshold=10)
def download_file_to_path(url, download_path, file_name):
    print("Download path: ", download_path)
    if not os.path.exists(download_path):
        os.makedirs(download_path, exist_ok=True)
    r = requests.get(url)
    dl_path = os.path.join(download_path, file_name)
    with open(dl_path, 'wb') as file:
        file.write(r.content)

def unzip_files_to_directory(zip_path, extract_path, zip_filename):
    try:
        if not os.path.exists(extract_path):
            os.makedirs(extract_path, exist_ok=True)
        z = zipfile.ZipFile(os.path.join(zip_path, zip_filename))
        z.extractall(extract_path)
        print(zip_filename + ' unzipped successfully')
        print('---------')
        z.close()
        current_os = platform.system()
        if (current_os == "Linux" or current_os == "Darwin"):
            file_to_delete = f'{extract_path}' + f'/{zip_filename}'
        elif current_os == "Windows":
            file_to_delete = f'{extract_path}' + f'\\{zip_filename}'
        os.remove(file_to_delete)
    except zipfile.BadZipfile as e:
        print("Error while unzipping data" + e)

def transform_xml_files_to_json(path):
    directory_contents = os.listdir(path)

    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".xml") and os.path.isfile(item_path):
            xml_file_to_json(item_path)
            os.remove(item_path)

def transform_big_json_files_to_multiple_json_files(path, output_prefix, json_array_path):
    directory_contents = os.listdir(path)

    for item in directory_contents:
        item_path = os.path.join(path, item)
        if item_path.endswith(".json") and os.path.isfile(item_path):
            slice_json_file(item_path, path, output_prefix, 200, json_array_path)


# Convert XML Files to JSON Files
def xml_file_to_json(xmlFile):
    # parse the import folder for xml files
    # open the input xml file and read
    # data in form of python dictionary
    # using xmltodict module
    print(f"Transforming file {xmlFile}")
    if xmlFile.endswith(".xml"):
        with open(xmlFile, 'r', encoding='utf-8') as xml_file:
            data_dict = xmltodict.parse(xml_file.read())
            xml_file.close()
            # generate the object using json.dumps()
            # corresponding to json data
            json_data = json.dumps(data_dict)
            # Write the json data to output
            # json file
            xml_file.close()
        jsonfile = f'{xmlFile}'
        print(jsonfile)
        jsonfile = jsonfile.replace(".xml", ".json")
        print(jsonfile)
        with open(jsonfile, "w") as json_file:
            json_file.write(json_data)
            json_file.close()

# Flatten CWE Dataset File
def replace_unwanted_string_cwe(path):
    listOfFiles = os.listdir(path)
    pattern = "*.json"
    files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("cwec"):
                files.append(entry)
                break
    file = path + files[0]
    fin = open(file, "rt")
    flattened_cwe = path + "cwe.json"
    fout = open(flattened_cwe, "wt")
    for line in fin:
        fout.write(line.replace('"@', '"'))
    fin.close()
    os.remove(file)
    fout.close()

# Flatten CAPEC Dataset File
def replace_unwanted_string_capec(path):
    listOfFiles = os.listdir(path)
    pattern = "*.json"
    files = []
    for entry in listOfFiles:
        if fnmatch.fnmatch(entry, pattern):
            if entry.startswith("capec"):
                files.append(entry)
                break
    file = path + files[0]
    fin = open(file, "rt")
    flattened_cwe = path + "capec.json"
    fout = open(flattened_cwe, "wt")
    for line in fin:
        fout.write(line.replace('"@', '"').replace('#text', 'text'))
    fin.close()
    fout.close()
    os.remove(file)

def slice_json_file(input_file, output_path, output_prefix, batch_size, json_array_path):
    with open(input_file, 'r') as f:
        data = json.load(f)

    data_array = select_nested_array_by_path(data, json_array_path)
    length = len(data_array)

    if not os.path.exists(os.path.join(output_path, "splitted")):
        os.makedirs(os.path.join(output_path, "splitted"), exist_ok=True)

    for i in range(0, length, batch_size):
        batch = data_array[i:i+batch_size]
        output_file = f"{output_path}/splitted/{output_prefix}_output_file_{i//batch_size + 1}.json"
        with open(output_file, 'w') as f_out:
            json.dump(batch, f_out, indent=4)

def select_nested_array_by_path(json_data, path):
    parsed_json = json_data
    keys = path.split('.')

    for key in keys:
        if key in parsed_json:
            parsed_json = parsed_json[key]
        else:
            return None

    return parsed_json

def run_dos2unix(file):
    print(f"Normalizing line endings for {file}")
    dos2unix_binary = shutil.which("dos2unix")

    if dos2unix_binary:
        try:
            process = subprocess.run([dos2unix_binary, file], capture_output=True, text=True, check=True)
            if process.returncode == 0:
                print(f"File {file} transformed to unix format")
            else:
                raise RuntimeError(f"Error running dos2unix command: {process.stderr.strip()}")
            return
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Error running dos2unix command. Make sure dos2unix is installed and check your file. Error: {e}") from e
        except FileNotFoundError:
            # Fall back to manual normalization below if the binary disappears mid-run
            pass

    # Fallback: normalize in Python when dos2unix is unavailable
    try:
        with open(file, "rb") as f:
            content = f.read()
        normalized = content.replace(b"\r\n", b"\n")
        with open(file, "wb") as f:
            f.write(normalized)
        print(f"File {file} normalized without dos2unix binary")
    except FileNotFoundError as e:
        raise RuntimeError(f"File not found for normalization: {file}") from e
    except OSError as e:
        raise RuntimeError(f"Failed to normalize line endings for {file}: {e}") from e
