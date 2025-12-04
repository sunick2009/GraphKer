# Neo4j APOC File Import Flow (Containerized Neo4j)

Use this when you want Neo4j (in a Docker container) to load the downloaded batches via `apoc.load.json`, which is faster than direct-ingest for full datasets.

## 1) Download and prepare batches on the host
```bash
# from repo root
uv run python main.py -d IMPORT_PATH --download-only
# Files produced under IMPORT_PATH:
#   nist/cve/splitted/*.json (CVE)
#   nist/cpe/splitted/*.json (CPE) if enabled
#   mitre_cwe/splitted/*.json (CWE)
#   mitre_capec/splitted/*.json (CAPEC)
#   *.cypher (schema/data scripts)
```

## 2) Copy files into the Neo4j container import directory
```bash
docker cp IMPORT_PATH/. neo4j:/var/lib/neo4j/import
docker exec neo4j chown -R neo4j:neo4j /var/lib/neo4j/import
```
Alternatively, mount a volume when running Neo4j:
```bash
docker run ... -v /absolute/path/IMPORT_PATH:/var/lib/neo4j/import ...
```

## 3) Run the ingestion (APOC file mode)
Run from the host, pointing to the container’s import path, without `--direct-ingest`:
```bash
uv run python main.py \
  -u bolt://<neo4j-host>:7687 -n <user> -p <password> \
  -d /var/lib/neo4j/import --reuse-downloads
```
- `--reuse-downloads` avoids re-downloading or clearing local batches.
- Keep `NVD_SOURCE`/API settings in `.env` as needed for downloads.

## Notes
- Ensure Neo4j config allows APOC file access (`apoc.import.file.enabled=true`) and the import directory is readable by the `neo4j` user.
- If CPE downloads require no API key on your server, set `NVD_ALLOW_CPE_NO_KEY=true` in `.env` before running step 1.
- For quick verification, you can add `--direct-limit N` (with `--direct-ingest`) instead of APOC; for full loads, APOC is recommended.
