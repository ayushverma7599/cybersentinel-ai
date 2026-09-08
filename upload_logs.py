#!/usr/bin/env python3
import json
import os
import requests
from datetime import datetime

log_dir = "/home/kali/honeypot/cowrie-data/log"
es_url = "http://localhost:9200"

# Read all JSON logs
for filename in os.listdir(log_dir):
    if filename.endswith('.json'):
        print(f"Processing {filename}...")
        with open(os.path.join(log_dir, filename), 'r') as f:
            for line in f:
                try:
                    log = json.loads(line)
                    
                    # Get timestamp
                    ts = log.get('timestamp', datetime.now().isoformat())
                    
                    # Create index name
                    date_part = ts.split('T')[0]
                    index_name = f"cowrie-{date_part}"
                    
                    # Upload to Elasticsearch
                    response = requests.post(
                        f"{es_url}/{index_name}/_doc",
                        json=log,
                        headers={"Content-Type": "application/json"}
                    )
                    
                    if response.status_code == 201:
                        print(f"  ✓ Uploaded 1 log")
                    else:
                        print(f"  ✗ Error: {response.status_code}")
                except Exception as e:
                    print(f"  Error: {e}")

print("Done!")
