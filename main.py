# VT Checker
# README :
# Import requests
import private.config as config
import requests
import json
import logging
import time
import math
import collections
import os.path
import hashlib
import pprint




def __init__(self):
    self.VTapi = config.parse['virustotal']['api']
    self.VTURL = config.parse['virustotal']['url']


def get_analysis(analysis, wait):
    for key in analysis:
        print(key)
        logging.warning('URL : %s ; H256 : %s', self.VTURL, key)
        params = dict(apikey=self.VTapi, resource=analysis)
        response = requests.get(self.VTURL, params=params)
        logging.warning('Waiting for %s seconds...', wait)
        logging.warning('URL : %s ; HTTP Response code : %s', self.VTURL, response.status_code)

        time.sleep(wait)
    return response.json()

if __name__ == '__main__':
    log(format)
    #db = get_files("C:\\Users\\math\\OneDrive - VINCI Autoroutes\\99 - Dev\\.idea")

    #print(db["6172c5997eeb3cd19c9ca2b5b97d6e2983cdd1fa60b2460d7bbb74055edcaa46"])
    result = get_analysis(db, wait)
    #print(len(db.keys()))


    #parsed = json.loads(result)
    #print(json.dumps(parsed, indent=4, sort_keys=True))
    #print(result["positives"])
