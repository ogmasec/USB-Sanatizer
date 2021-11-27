# VT Checker
# README :
# Import requests

import requests
import json
import logging
import time
import math
import collections
import os.path
import hashlib
import pprint

analysis_id = "8c7ccefa5576b1be7fdc9d59fa1185ab64469b88696d195e61b4a12b9dee7d5e"
format = '%(asctime)s ; %(message)s '
wait = 10


def get_file_hash(filename):
    with open(filename,"rb") as f:
        bytes = f.read() # read entire file as bytes
        readable_hash = hashlib.sha256(bytes).hexdigest();
        return readable_hash

def log(format):
    logging.basicConfig(format=format)

def get_analysis(analysis, wait):
    api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
    for key in analysis:
        print(key)
        logging.warning('URL : %s ; H256 : %s', api_url, key)
        params = dict(apikey=api_key, resource=analysis)
        response = requests.get(api_url, params=params)
        logging.warning('Waiting for %s seconds...', wait)
        logging.warning('URL : %s ; HTTP Response code : %s', api_url, response.status_code)

        time.sleep(wait)
    return response.json()

def get_entropy(file):
    print("entro")
    with open(file,"rb") as f:
        bytes = f.read()

        #Get file entropy
        #source https://blog.cugu.eu/post/fast-python-file-entropy/
        e = 0
        counter = collections.Counter(bytes)
        l = len(bytes)
        for count in counter.values():
            # count is always > 0
            p_x = count / l
            e += - p_x * math.log2(p_x)
    return e


def get_files(root):
    # Grab USB key and get SHA256
    db = {}
    for path, subdirs, files in os.walk(root):
        for name in files:
            path = os.path.join(path, name)
            sha256 = get_file_hash(path)
            db[sha256] = path
    return db

if __name__ == '__main__':
    log(format)
    db = get_files("C:\\Users\\math\\OneDrive - VINCI Autoroutes\\99 - Dev\\.idea")

    print(db["6172c5997eeb3cd19c9ca2b5b97d6e2983cdd1fa60b2460d7bbb74055edcaa46"])
    #result = get_analysis(db, wait)
    #print(len(db.keys()))


    #parsed = json.loads(result)
    #print(json.dumps(parsed, indent=4, sort_keys=True))
    #print(result["positives"])
