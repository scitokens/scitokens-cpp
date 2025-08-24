#!/usr/bin/env python3

import os
import json
import requests
import subprocess
import sys


def get_demo_token(payload: dict):
    data = json.dumps({'algorithm': "ES256", 'payload': payload})
    resp = requests.post("https://demo.scitokens.org/issue", data=data)
    return resp.text


demo_payload = {
    "ver": "scitoken:2.0",
    "aud": "https://demo.scitokens.org",
    "iss": "https://demo.scitokens.org",
}
demo_token = get_demo_token(demo_payload)

try:
    scitokens_cache = f"{os.getcwd()}/scitokens/scitokens_cpp.sqllite"
    os.unlink(scitokens_cache)
except FileNotFoundError:
    pass

rv = subprocess.run(
    ['./scitokens-asynch-test', demo_token],
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    timeout=5,
    universal_newlines=True,
)

print(rv.stdout)
sys.exit(rv.returncode)
