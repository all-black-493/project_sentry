from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import os

url = os.getenv("ELASTICSEARCH_URL")
es = Elasticsearch(url, request_timeout=10, verify_certs=False)

end_time = datetime.now()
start_time = end_time - timedelta(hours=24)

query = {
    "size": 1000,
    "query": {
        "bool": {
            "must": [
                {"match": {"event": "detection"}},
                {"range": {"anomalyScore": {"gte": 0.9}}},
                {
                    "range": {
                        "@timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat(),
                        }
                    }
                },
            ]
        }
    },
}

response = es.search(index="blue-agent-logs-*", body=query)

with open("signatures.json", "r") as f:
    signatures = json.load(f)

new_signatures = set(signatures)

for hit in response["hits"]["hits"]:
    snippet = hit["_source"].get("promptSnippet", "").strip()
    if snippet and snippet not in new_signatures:
        new_signatures.add(snippet)

with open("signatures.json", "w") as f:
    json.dump(sorted(new_signatures), f, indent=2)

print(f"Added {len(new_signatures) - len(signatures)} new signatures")
