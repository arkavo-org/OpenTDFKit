#!/bin/bash
curl -s -X POST http://10.0.0.138:8888/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d grant_type=client_credentials \
  -d client_id=opentdf-client \
  -d client_secret=secret