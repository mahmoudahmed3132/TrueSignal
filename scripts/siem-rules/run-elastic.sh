#!/usr/bin/env bash
# Start a throwaway Elasticsearch + Kibana (8.19.22, digest-pinned) in Docker,
# run the TrueSignal Elastic rules against the Hub's sample output
# (run-elastic.py), then remove the containers.
#
#   scripts/siem-rules/run-elastic.sh
#   TS_IMAGE_REGISTRY=mirror.gcr.io/library scripts/siem-rules/run-elastic.sh   # Docker Hub mirror
#   KEEP=1 scripts/siem-rules/run-elastic.sh                                    # leave the stack running
#
# Needs docker, curl, python3 and ~4 GB of free memory. Uses ports 9200 and
# 5601 on 127.0.0.1. Test-only credentials; never point this at a real stack.
set -euo pipefail

REG="${TS_IMAGE_REGISTRY:-docker.io/library}"
ES_IMAGE="$REG/elasticsearch:8.19.22@sha256:909a569c9c973d1de81cee7a002b69e65726f8d6317de4627ccfeb690a6d0ccb"
KB_IMAGE="$REG/kibana:8.19.22@sha256:4116dd6a58380c79acb51e21d1bc00c68219baeaa8f66de25f476c72920edf1f"
PASS="changeme-test"
KB_PASS="changeme-kib"
NET="ts-siem-rules"
ES="ts-siem-rules-es"
KB="ts-siem-rules-kb"

cleanup() {
  if [ "${KEEP:-0}" != "1" ]; then
    docker rm -f "$ES" "$KB" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$ES" "$KB" >/dev/null 2>&1 || true

docker run -d --name "$ES" --net "$NET" -p 127.0.0.1:9200:9200 \
  -e discovery.type=single-node -e ELASTIC_PASSWORD="$PASS" \
  -e xpack.security.enabled=true -e xpack.security.http.ssl.enabled=false \
  -e cluster.routing.allocation.disk.threshold_enabled=false \
  -e ES_JAVA_OPTS="-Xms1g -Xmx1g" "$ES_IMAGE" >/dev/null

echo "waiting for Elasticsearch..."
for _ in $(seq 1 90); do
  curl -sf -u "elastic:$PASS" "http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=5s" >/dev/null 2>&1 && break
  sleep 2
done
curl -sf -u "elastic:$PASS" -X POST "http://127.0.0.1:9200/_security/user/kibana_system/_password" \
  -H 'Content-Type: application/json' -d "{\"password\":\"$KB_PASS\"}" >/dev/null

docker run -d --name "$KB" --net "$NET" -p 127.0.0.1:5601:5601 \
  -e ELASTICSEARCH_HOSTS="http://$ES:9200" -e ELASTICSEARCH_USERNAME=kibana_system -e ELASTICSEARCH_PASSWORD="$KB_PASS" \
  -e XPACK_ENCRYPTEDSAVEDOBJECTS_ENCRYPTIONKEY=test-only-0123456789abcdef0123456789 \
  -e XPACK_SECURITY_ENCRYPTIONKEY=test-only-0123456789abcdef0123456789 \
  "$KB_IMAGE" >/dev/null

echo "waiting for Kibana..."
for _ in $(seq 1 120); do
  curl -sf -u "elastic:$PASS" "http://127.0.0.1:5601/api/status" 2>/dev/null | grep -q '"level":"available"' && break
  sleep 3
done

python3 "$(dirname "$0")/run-elastic.py" --es http://127.0.0.1:9200 --kibana http://127.0.0.1:5601 --user elastic --password "$PASS"
