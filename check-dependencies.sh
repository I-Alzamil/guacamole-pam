#!/bin/bash
# Checks every library the extension depends on against the OSV database of
# known vulnerabilities (osv.dev), sending it their names and versions only.
# Fails if one the jar bundles is affected; those Guacamole provides
# (scope "provided"), or only the unit tests use, are listed, as upgrading
# Guacamole, or the tests, changes them.
cd "$(dirname "$0")" || exit 2
list=$(mktemp) && trap 'rm -f "$list"' EXIT
mvn --batch-mode --quiet dependency:list -DoutputFile="$list" -DincludeScope=test || exit 2
python3 -I - "$list" <<'PY'
import json, sys, urllib.request

deps = []
for line in open(sys.argv[1]):
    parts = line.strip().split(" ")[0].split(":")
    if len(parts) >= 5:
        deps.append((parts[0] + ":" + parts[1], parts[3], parts[4]))

query = {"queries": [{"package": {"ecosystem": "Maven", "name": name}, "version": version}
                     for name, version, _ in deps]}
request = urllib.request.Request("https://api.osv.dev/v1/querybatch", json.dumps(query).encode(),
                                 {"Content-Type": "application/json"})
results = json.load(urllib.request.urlopen(request, timeout=60))["results"]

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
