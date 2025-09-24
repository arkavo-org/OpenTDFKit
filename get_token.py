#!/usr/bin/env python3
import requests
import json
import sys

# Try to get token
url = "http://10.0.0.138:8080/auth/token"
data = {
    "grant_type": "client_credentials",
    "client_id": "opentdf-client",
    "client_secret": "secret"
}

try:
    response = requests.post(url, data=data)
    if response.status_code == 200:
        token = response.json().get("access_token")
        if token:
            with open("fresh_token.txt", "w") as f:
                f.write(token)
            print("Token saved to fresh_token.txt")
        else:
            print("No access_token in response")
            print(response.text)
    else:
        print(f"Failed with status {response.status_code}")
        print(response.text)
except Exception as e:
    print(f"Error: {e}")