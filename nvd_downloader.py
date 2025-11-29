"""
Utilities for downloading and normalizing NVD CVE/CPE data.

The default implementation targets the FKIE-CAD GitHub mirror of the
NVD 2.0 JSON feeds (distributed as ``.xz`` archives).  The resulting CVE
records are normalized to a shape that mimics the legacy ``data-feeds``
structure used by the existing Neo4j Cypher scripts.

Optional support for the NVD 2.0 API is provided for scenarios where an
API key is available (e.g. for fetching CPE data which is not mirrored).
"""
from __future__ import annotations

import datetime
import json
import lzma
import os
import time
from dataclasses import dataclass, field
from io import BytesIO
from typing import Dict, Generator, Iterable, List, Optional

import requests

MIRROR_BASE = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
API_BASE = "https://services.nvd.nist.gov/rest/json"


@dataclass
class NVDSourceConfig:
    """Configuration for selecting the NVD source and scope.

    Attributes:
        source: ``"mirror"`` to use the FKIE-CAD GitHub mirror (default),
            or ``"api"`` to query the NVD 2.0 API directly.
        api_key: Optional API key used when ``source`` is ``"api"``.
        years: Explicit list of years to fetch full CVE feeds for. When
            ``None`` only the *Recent* and *Modified* feeds are pulled.
    """

    source: str = "mirror"
    api_key: Optional[str] = None
    years: Optional[List[int]] = field(default=None)

    @classmethod
    def from_env(cls) -> "NVDSourceConfig":
        years_env = os.getenv("NVD_YEARS")
        years: Optional[List[int]] = None
        if years_env:
            if years_env.strip().lower() == "all":
                current_year = datetime.datetime.utcnow().year
                years = list(range(1999, current_year + 1))
            else:
                years = [int(y) for y in years_env.split(",") if y.strip().isdigit()]
        return cls(
            source=os.getenv("NVD_SOURCE", "mirror"),
            api_key=os.getenv("NVD_API_KEY"),
            years=years,
        )


class NVDMirrorClient:
    """Download CVE data from the FKIE-CAD GitHub mirror."""

    session: requests.Session

    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "GraphKer-NVD-Mirror"})

    def iter_cve_items(self, years: Optional[Iterable[int]] = None) -> Generator[Dict, None, None]:
        """Yield CVE items from the mirror, normalizing to legacy structure."""

        feed_names = ["CVE-Recent.json.xz", "CVE-Modified.json.xz"]
        if years:
            for year in years:
                feed_names.append(f"CVE-{year}.json.xz")

        for feed in feed_names:
            url = f"{MIRROR_BASE}/{feed}"
            for item in self._download_and_parse_feed(url):
                yield item

    def _download_and_parse_feed(self, url: str) -> Generator[Dict, None, None]:
        response = self.session.get(url, timeout=120)
        response.raise_for_status()
        with lzma.LZMAFile(BytesIO(response.content)) as compressed:
            raw = json.loads(compressed.read().decode("utf-8"))
        items = raw.get("cve_items") or raw.get("CVE_Items") or []
        for item in items:
            yield normalize_cve_item(item)


class NVDApiClient:
    """Client for the official NVD 2.0 API."""

    def __init__(self, api_key: Optional[str] = None) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "GraphKer-NVD-API"})
        if api_key:
            self.session.headers["apiKey"] = api_key
        self.api_key = api_key

    def iter_cve_items(self, start_index: int = 0, results_per_page: int = 2000) -> Generator[Dict, None, None]:
        """Iterate through CVE items from the NVD API."""

        total_results: Optional[int] = None
        index = start_index
        while True:
            payload = {
                "resultsPerPage": results_per_page,
                "startIndex": index,
            }
            data = self._get("/cves/2.0", payload)
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_item = vuln.get("cve") or vuln
                yield normalize_cve_item(cve_item)
            if total_results is None:
                total_results = data.get("totalResults")
            index += data.get("resultsPerPage", len(vulnerabilities))
            if total_results is None or index >= total_results or not vulnerabilities:
                break
            time.sleep(0.6 if self.api_key else 6)

    def iter_cpe_items(self, start_index: int = 0, results_per_page: int = 500) -> Generator[Dict, None, None]:
        """Iterate CPE items from the NVD API."""

        total_results: Optional[int] = None
        index = start_index
        while True:
            payload = {
                "resultsPerPage": results_per_page,
                "startIndex": index,
            }
            data = self._get("/cpes/2.0", payload)
            products = data.get("products", [])
            for product in products:
                cpe_name = product.get("cpeName", {})
                children = product.get("cpeNameMatch", [])
                yield {
                    "cpe23Uri": cpe_name.get("cpe23Uri"),
                    "cpe_name": [
                        {"cpe23Uri": child.get("criteria"), "vulnerable": child.get("vulnerable")}
                        for child in children
                        if child.get("criteria")
                    ],
                }
            if total_results is None:
                total_results = data.get("totalResults")
            index += data.get("resultsPerPage", len(products))
            if total_results is None or index >= total_results or not products:
                break
            time.sleep(0.6 if self.api_key else 6)

    def _get(self, path: str, params: Dict) -> Dict:
        response = self.session.get(API_BASE + path, params=params, timeout=120)
        if response.status_code == 429:
            # Rate limited - simple backoff
            time.sleep(2)
            response = self.session.get(API_BASE + path, params=params, timeout=120)
        response.raise_for_status()
        return response.json()


def normalize_cve_item(raw_item: Dict) -> Dict:
    """Normalize CVE items from either mirror feeds or the API.

    The goal is to mimic the legacy ``nvdcve`` JSON structure used by the
    existing Cypher scripts so that downstream ingestion remains stable.
    """

    item = raw_item.get("cve") if "cve" in raw_item else raw_item
    cve_meta = {
        "ID": item.get("id"),
        "ASSIGNER": item.get("sourceIdentifier"),
    }

    description_data = item.get("descriptions", [])
    problemtype_data = [
        {"description": weakness.get("description", [])}
        for weakness in item.get("weaknesses", [])
    ]
    reference_data = [
        {
            "url": ref.get("url"),
            "name": ref.get("url"),
            "refsource": ref.get("source"),
        }
        for ref in item.get("references", [])
    ]

    normalized: Dict = {
        "cve": {
            "CVE_data_meta": cve_meta,
            "description": {"description_data": description_data},
            "problemtype": {"problemtype_data": problemtype_data},
            "references": {"reference_data": reference_data},
        },
        "publishedDate": item.get("published"),
        "lastModifiedDate": item.get("lastModified"),
    }

    metrics = item.get("metrics", {})
    cvss_v3 = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or [])
    if cvss_v3:
        metric = cvss_v3[0]
        cvss = metric.get("cvssData", {})
        normalized["impact"] = normalized.get("impact", {})
        normalized["impact"]["baseMetricV3"] = {
            "cvssV3": {
                "version": cvss.get("version"),
                "vectorString": cvss.get("vectorString"),
                "attackVector": cvss.get("attackVector"),
                "attackComplexity": cvss.get("attackComplexity"),
                "privilegesRequired": cvss.get("privilegesRequired"),
                "userInteraction": cvss.get("userInteraction"),
                "scope": cvss.get("scope"),
                "confidentialityImpact": cvss.get("confidentialityImpact"),
                "integrityImpact": cvss.get("integrityImpact"),
                "availabilityImpact": cvss.get("availabilityImpact"),
                "baseScore": cvss.get("baseScore"),
                "baseSeverity": cvss.get("baseSeverity"),
            },
            "exploitabilityScore": metric.get("exploitabilityScore"),
            "impactScore": metric.get("impactScore"),
        }

    cvss_v2 = metrics.get("cvssMetricV2", [])
    if cvss_v2:
        metric = cvss_v2[0]
        cvss = metric.get("cvssData", {})
        normalized.setdefault("impact", {})["baseMetricV2"] = {
            "cvssV2": {
                "version": cvss.get("version"),
                "vectorString": cvss.get("vectorString"),
                "accessVector": cvss.get("accessVector"),
                "accessComplexity": cvss.get("accessComplexity"),
                "authentication": cvss.get("authentication"),
                "confidentialityImpact": cvss.get("confidentialityImpact"),
                "integrityImpact": cvss.get("integrityImpact"),
                "availabilityImpact": cvss.get("availabilityImpact"),
                "baseScore": cvss.get("baseScore"),
            },
            "severity": metric.get("baseSeverity"),
            "impactScore": metric.get("impactScore"),
            "exploitabilityScore": metric.get("exploitabilityScore"),
            "acInsufInfo": metric.get("acInsufInfo"),
            "obtainAllPrivilege": metric.get("obtainAllPrivilege"),
            "obtainUserPrivilege": metric.get("obtainUserPrivilege"),
            "obtainOtherPrivilege": metric.get("obtainOtherPrivilege"),
            "userInteractionRequired": metric.get("userInteractionRequired"),
        }

    configurations = item.get("configurations")
    if configurations:
        raw_nodes = []
        if isinstance(configurations, dict):
            raw_nodes = configurations.get("nodes", [])
        elif isinstance(configurations, list):
            raw_nodes = configurations

        nodes_output: List[Dict] = []
        for node in raw_nodes:
            children_output: List[Dict] = []
            cpe_matches = [
                normalize_cpe_match(match) for match in node.get("cpeMatch", [])
            ]
            if cpe_matches:
                children_output.append({"cpe_match": cpe_matches})
            for child in node.get("children", []):
                child_matches = [normalize_cpe_match(match) for match in child.get("cpeMatch", [])]
                if child_matches:
                    children_output.append({"cpe_match": child_matches})
            for nested in node.get("nodes", []):
                nested_matches = [normalize_cpe_match(match) for match in nested.get("cpeMatch", [])]
                if nested_matches:
                    children_output.append({"cpe_match": nested_matches})
            if children_output:
                nodes_output.append({"children": children_output})
        if nodes_output:
            normalized["configurations"] = {"nodes": nodes_output}

    return normalized


def normalize_cpe_match(match: Dict) -> Dict:
    return {
        "cpe23Uri": match.get("criteria") or match.get("cpe23Uri"),
        "vulnerable": match.get("vulnerable"),
        "versionStartIncluding": match.get("versionStartIncluding"),
        "versionEndIncluding": match.get("versionEndIncluding"),
        "versionStartExcluding": match.get("versionStartExcluding"),
        "versionEndExcluding": match.get("versionEndExcluding"),
    }


def write_cve_batches(
    items: Iterable[Dict], output_path: str, batch_size: int = 200
) -> List[str]:
    """Persist CVE items into batch JSON files for APOC ingestion."""

    os.makedirs(os.path.join(output_path, "splitted"), exist_ok=True)
    batch_files: List[str] = []
    batch: List[Dict] = []
    batch_index = 1

    for item in items:
        batch.append(item)
        if len(batch) >= batch_size:
            file_path = _write_batch(batch, output_path, batch_index)
            batch_files.append(file_path)
            batch_index += 1
            batch = []

    if batch:
        file_path = _write_batch(batch, output_path, batch_index)
        batch_files.append(file_path)

    return batch_files


def _write_batch(batch: List[Dict], output_path: str, index: int) -> str:
    file_path = os.path.join(output_path, "splitted", f"cve_output_file_{index}.json")
    with open(file_path, "w", encoding="utf-8") as f_out:
        json.dump(batch, f_out, indent=2)
    return file_path


def write_cpe_batches(
    items: Iterable[Dict], output_path: str, batch_size: int = 1000
) -> List[str]:
    os.makedirs(os.path.join(output_path, "splitted"), exist_ok=True)
    batch_files: List[str] = []
    batch: List[Dict] = []
    batch_index = 1

    for item in items:
        if not item.get("cpe23Uri"):
            continue
        batch.append(item)
        if len(batch) >= batch_size:
            file_path = _write_cpe_batch(batch, output_path, batch_index)
            batch_files.append(file_path)
            batch_index += 1
            batch = []
    if batch:
        file_path = _write_cpe_batch(batch, output_path, batch_index)
        batch_files.append(file_path)
    return batch_files


def _write_cpe_batch(batch: List[Dict], output_path: str, index: int) -> str:
    file_path = os.path.join(output_path, "splitted", f"cpe_output_file_{index}.json")
    with open(file_path, "w", encoding="utf-8") as f_out:
        json.dump(batch, f_out, indent=2)
    return file_path
