#!/bin/bash
# Checks every library the extension depends on against the OSV database of
# known vulnerabilities (osv.dev), sending it their names and versions only.
# Fails (1) if one the jar bundles is affected; those Guacamole provides
# (scope "provided"), or only the unit tests use, are listed, as upgrading
# Guacamole, or the tests, changes them. Fails with 2 if the check itself
# could not run, or found no library, so a broken check never passes.
cd "$(dirname "$0")" || exit 2
list=$(mktemp) || exit 2
trap 'rm -f "$list"' EXIT
mvn --batch-mode --quiet dependency:list -DoutputFile="$list" -DincludeScope=test || exit 2
python3 -I - "$list" <<'PY'
import json, sys, urllib.request

# group:artifact:type[:classifier]:version:scope, perhaps followed by
# " -- module ..." (read from the end, as a classifier shifts the rest)
deps = []
for line in open(sys.argv[1]):
    parts = line.strip().split(" ")[0].split(":")
    if len(parts) >= 5:
        deps.append((parts[0] + ":" + parts[1], parts[-2], parts[-1]))

if not deps:
    print("No library found in the dependency list: the check cannot run.")
    sys.exit(2)

query = {"queries": [{"package": {"ecosystem": "Maven", "name": name}, "version": version}
                     for name, version, _ in deps]}
request = urllib.request.Request("https://api.osv.dev/v1/querybatch", json.dumps(query).encode(),
                                 {"Content-Type": "application/json"})
try:
    results = json.load(urllib.request.urlopen(request, timeout=60))["results"]
except Exception as e:
    print("Unable to query osv.dev: %s" % e)
    sys.exit(2)
if len(results) != len(deps):
    print("osv.dev answered for %d libraries of %d: the check cannot be trusted." % (len(results), len(deps)))
    sys.exit(2)

bundled = 0
for (name, version, scope), result in zip(deps, results):
    ids = [vuln["id"] for vuln in result.get("vulns", [])]
    if not ids:
        continue
    shipped = scope in ("compile", "runtime")
    bundled += shipped
    label = "VULNERABLE, bundled:" if shipped else "provided by Guacamole:" if scope == "provided" else "tests only:"
    print("%s %s %s: %s" % (label, name, version, ", ".join(ids)))
print("%d libraries checked; %d bundled in the jar with known vulnerabilities." % (len(deps), bundled))
sys.exit(1 if bundled else 0)
PY
