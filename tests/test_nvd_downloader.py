import os
import sys
from itertools import islice
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from nvd_downloader import NVDMirrorClient, write_cve_batches


def test_mirror_recent_feed_parses(tmp_path):
    client = NVDMirrorClient()
    items = []
    has_config = False
    for item in client.iter_cve_items():
        items.append(item)
        has_config = has_config or "configurations" in item
        if len(items) >= 800 or (len(items) >= 200 and has_config):
            break

    assert items, "Mirror feed should provide CVE items"

    ids = [item["cve"]["CVE_data_meta"].get("ID") for item in items]
    assert any(ids), "CVE IDs should be present in normalized items"

    descriptions = [item["cve"]["description"].get("description_data") for item in items]
    assert any(descriptions), "Descriptions should be populated from the feed"

    has_cvss = any(
        item.get("impact", {}).get("baseMetricV3") or item.get("impact", {}).get("baseMetricV2")
        for item in items
    )
    assert has_cvss, "At least one item should carry CVSS metrics"

    assert has_config, "At least one item should contain CPE configuration data"

    output_dir = tmp_path / "batches"
    batch_files = write_cve_batches(items, str(output_dir), batch_size=10)
    assert batch_files, "Batches should be written to disk"
    assert all(os.path.exists(path) for path in batch_files)
