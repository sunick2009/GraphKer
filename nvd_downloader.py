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
from collections import deque
from dataclasses import dataclass, field
from io import BytesIO
from typing import Dict, Generator, Iterable, List, Optional

import requests
from tqdm import tqdm
from loguru import logger

MIRROR_BASE_DEFAULT = "https://github.com/fkie-cad/nvd-json-data-feeds/releases/latest/download"
API_BASE_DEFAULT = "https://services.nvd.nist.gov/rest/json"
CVE_API_PATH_DEFAULT = "/cves/2.0"
CPE_API_PATH_DEFAULT = "/cpes/2.0"


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
        self.mirror_base = os.getenv("NVD_MIRROR_BASE", MIRROR_BASE_DEFAULT)

    def iter_cve_items(self, years: Optional[Iterable[int]] = None) -> Generator[Dict, None, None]:
        """Yield CVE items from the mirror, normalizing to legacy structure."""

        feed_names = ["CVE-Recent.json.xz", "CVE-Modified.json.xz"]
        if years:
            for year in years:
                feed_names.append(f"CVE-{year}.json.xz")

        for feed in feed_names:
            url = f"{self.mirror_base}/{feed}"
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
        self.api_base = os.getenv("NVD_API_BASE", API_BASE_DEFAULT)
        self.cve_path = os.getenv("NVD_API_CVE_PATH", CVE_API_PATH_DEFAULT)
        self.cpe_path = os.getenv("NVD_API_CPE_PATH", CPE_API_PATH_DEFAULT)
        self.cve_keyword = os.getenv("NVD_CVE_QUERY_KEYWORD", "*").strip()
        self.cpe_keyword = os.getenv("NVD_CPE_QUERY_KEYWORD", "*").strip()
        self.cve_results_per_page = int(os.getenv("NVD_CVE_PAGE_SIZE", "2000"))
        self.cpe_results_per_page = int(os.getenv("NVD_CPE_PAGE_SIZE", "10000"))
        self._rate_window = int(os.getenv("NVD_RATE_WINDOW", "30"))  # seconds
        default_limit = 50 if api_key else 5
        self._rate_limit = int(os.getenv("NVD_RATE_LIMIT", str(default_limit)))
        self._disable_rate_limit = os.getenv("NVD_RATE_DISABLED", "false").lower() in ("1", "true", "yes")
        self._request_timestamps: deque[float] = deque()

    def iter_cve_items(self, start_index: int = 0, results_per_page: Optional[int] = None) -> Generator[Dict, None, None]:
        """Iterate through CVE items from the NVD API."""

        page_size = results_per_page or self.cve_results_per_page
        total_results: Optional[int] = None
        index = start_index
        while True:
            payload = {
                "resultsPerPage": page_size,
                "startIndex": index,
            }
            if self.cve_keyword:
                payload["keywordSearch"] = self.cve_keyword
            try:
                data = self._get(self.cve_path, payload)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 400 and "page end" in (e.response.text or "").lower():
                    logger.warning(f"CVE page end at startIndex={index}, stopping iteration")
                    break
                raise
            vulnerabilities = data.get("vulnerabilities", [])
            for vuln in vulnerabilities:
                cve_item = vuln.get("cve") or vuln
                yield normalize_cve_item(cve_item)
            if total_results is None:
                total_results = data.get("totalResults")
            returned = len(vulnerabilities)
            if returned == 0:
                break
            index += returned
            if total_results is not None and index >= total_results:
                break
            if not self._disable_rate_limit:
                time.sleep(0.6 if self.api_key else 6)

    def iter_cpe_items(self, start_index: int = 0, results_per_page: Optional[int] = None) -> Generator[Dict, None, None]:
        """Iterate CPE items from the NVD API."""

        page_size = results_per_page or self.cpe_results_per_page
        total_results: Optional[int] = None
        index = start_index
        while True:
            payload = {
                "resultsPerPage": page_size,
                "startIndex": index,
            }
            if self.cpe_keyword:
                payload["keywordSearch"] = self.cpe_keyword
            try:
                data = self._get(self.cpe_path, payload)
            except requests.HTTPError as e:
                if e.response is not None and e.response.status_code == 400 and "page end" in (e.response.text or "").lower():
                    logger.warning(f"CPE page end at startIndex={index}, stopping iteration")
                    break
                raise
            products = data.get("products", [])
            for product in products:
                raw_cpe = product.get("cpeName") or product.get("cpe") or {}
                cpe_uri = None
                if isinstance(raw_cpe, dict):
                    cpe_uri = raw_cpe.get("cpe23Uri") or raw_cpe.get("cpeName")
                    children = raw_cpe.get("cpeNameMatch", [])
                else:
                    cpe_uri = raw_cpe
                    children = []

                children = product.get("cpeNameMatch", children) or []
                yield {
                    "cpe23Uri": cpe_uri,
                    "cpe_name": [
                        {"cpe23Uri": child.get("criteria") or child.get("cpe23Uri"), "vulnerable": child.get("vulnerable")}
                        for child in children
                        if child.get("criteria") or child.get("cpe23Uri")
                    ],
                }
            if total_results is None:
                total_results = data.get("totalResults")
            returned = len(products)
            if returned == 0:
                break
            index += returned
            if total_results is not None and index >= total_results:
                break
            if not self._disable_rate_limit:
                time.sleep(0.6 if self.api_key else 6)

    def _get(self, path: str, params: Dict) -> Dict:
        self._respect_rate_limit()
        url = self.api_base + path
        response = self.session.get(url, params=params, timeout=120)
        if response.status_code == 429:
            # Rate limited - simple backoff
            retry_after = response.headers.get("Retry-After")
            sleep_for = float(retry_after) if retry_after else 2
            time.sleep(sleep_for)
            self._respect_rate_limit()
            response = self.session.get(url, params=params, timeout=120)
        if response.status_code >= 400:
            snippet = response.text[:500] if response.text else ""
            logger.error(f"NVD API error {response.status_code} for {url} params={params} body={snippet}")
        response.raise_for_status()
        self._request_timestamps.append(time.time())
        return response.json()

    def _respect_rate_limit(self) -> None:
        """Throttle requests to honor NVD public/API rate limits (configurable via env)."""
        if self._disable_rate_limit or self._rate_limit <= 0:
            return
        now = time.time()
        while self._request_timestamps and now - self._request_timestamps[0] > self._rate_window:
            self._request_timestamps.popleft()
        if len(self._request_timestamps) >= self._rate_limit:
            sleep_for = self._rate_window - (now - self._request_timestamps[0]) + 0.1
            time.sleep(max(sleep_for, 0.1))


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

    description_data = item.get("descriptions") or []
    problemtype_data = [
        {"description": weakness.get("description", [])}
        for weakness in (item.get("weaknesses") or [])
        if weakness
    ]
    reference_data = [
        {
            "url": ref.get("url"),
            "name": ref.get("url"),
            "refsource": ref.get("source"),
        }
        for ref in (item.get("references") or [])
        if ref
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

    metrics = item.get("metrics") or {}
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

    configurations = item.get("configurations") or {}
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
    total_items = 0

    for item in tqdm(items, desc="CVE items", unit="cve", leave=False):
        batch.append(item)
        total_items += 1
        if len(batch) >= batch_size:
            file_path = _write_batch(batch, output_path, batch_index)
            batch_files.append(file_path)
            batch_index += 1
            batch = []

    if batch:
        file_path = _write_batch(batch, output_path, batch_index)
        batch_files.append(file_path)

    logger.info(f"CVE batches written: files={len(batch_files)} items={total_items} -> {output_path}")
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
    total_items = 0

    for item in tqdm(items, desc="CPE items", unit="cpe", leave=False):
        if not item.get("cpe23Uri"):
            continue
        batch.append(item)
        total_items += 1
        if len(batch) >= batch_size:
            file_path = _write_cpe_batch(batch, output_path, batch_index)
            batch_files.append(file_path)
            batch_index += 1
            batch = []
    if batch:
        file_path = _write_cpe_batch(batch, output_path, batch_index)
        batch_files.append(file_path)
    logger.info(f"CPE batches written: files={len(batch_files)} items={total_items} -> {output_path}")
    return batch_files


def _write_cpe_batch(batch: List[Dict], output_path: str, index: int) -> str:
    file_path = os.path.join(output_path, "splitted", f"cpe_output_file_{index}.json")
    with open(file_path, "w", encoding="utf-8") as f_out:
        json.dump(batch, f_out, indent=2)
    return file_path
