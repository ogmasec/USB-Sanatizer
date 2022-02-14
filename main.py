#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# VT Checker
# README :
# Import requests


import sys
import json
import time
import math
import pprint
import discord
import os.path
import hashlib
import requests
import collections
import configparser
from lib.logger import *
from dhooks import Webhook
from requests import session
from requests import HTTPError
import private.config as config

if sys.version_info.major < 3:
    from urlparse import urljoin
else:
    from urllib.parse import urljoin

class virustotal():
    def __init__(self,source):
        self.VTapi = config.parse[source]['api']
        self.VTURL = config.parse[source]['url']

    def getVTScore(self,hash):
        req = requests.get(self.VTURL,
                           params={"apikey": self.VTapi, 'resource': hash}, verify=False)
        try:
            req.raise_for_status()
            req = req.json()
        except HTTPError as e:
            error = str(e)
            return error, -1
        if req["response_code"] == 0:
            logger.info('Hash {} unknow in VT'.format(hash))
            # Nothing found
            return -1, -1
        if req:
            return req
class HybridAnalysis(object):
    """
    Hybrid Analysis REST API wrapper
    """
    __api_root = config.parse["hybrid-analysis"]["url"]
    def __init__(self, user_agent='Falcon Sandbox'):
        self.session = session()
        self.session.headers = {
            'api-key': config.parse["hybrid-analysis"]["api"],
            'user-agent': user_agent
        }

    def __connect(self, method, url_path, **kwargs):
        response = self.session.request(method, urljoin(self.__api_root, url_path), **kwargs)
        response.raise_for_status()

        if response.headers['Content-Type'] == 'application/json':
            return response.json()
        return response.content

    def search_hash(self, file_hash):
        """
        Summary for a given hash
        :param file_hash: MD5, SHA1 or SHA256
        :return:
        """
        return self.__connect('POST', 'search/hash', data={'hash': file_hash})


"""
class usbWalk(root) :
    def __init__(self):
        print("construct")

    def get_files(self,root):
        db = {}
        for path, subdirs, files in os.walk(root):
            for name in files:
                pwd = os.path.join(path, name)
                sha256,sha1,md5 = self.get_file_hash(pwd)
                db[sha256] = {"path":pwd,"md5":md5,"sha1":sha1}
        return db

    def get_file_hash(self,filename):
        with open(filename,"rb") as f:
            bytes = f.read() # read entire file as bytes
            sha256 = hashlib.sha256(bytes).hexdigest()
            sha1 = hashlib.sha1(bytes).hexdigest()
            md5 = hashlib.md5(bytes).hexdigest()
            return sha256,sha1,md5

    def get_entropy(self,file):
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
"""
def WebHook(checker,sha256,db):
    hook = Webhook(config.parse["webhook"]["discord"])
    embed = discord.Embed( description="Path : "+db["path"]+"\r\n"+"sha256 : "+sha256+"\r\nEntropy : "+str(db["entropy"]))
    embed.set_author(name=checker+" matches "+str(db[checker]), url=db["permalink"],
                     icon_url=config.parse[checker]["logo"])
    hook.send(embed=embed)
if __name__ == '__main__':
    logger.info(' --> New analysis')
    #walk = usbWalk()
    VTcheck = virustotal("virustotal")
    ha = HybridAnalysis()

    #db = walk.get_files("C:\\Users\\math\\Downloads")

    ####### Check #######
    #getting the results form a foler (USB Key?)
    for sha256 in db:
        ha_scan = ha.search_hash(sha256) ## Getting hybrid analysis results
        db[sha256]["entropy"] = walk.get_entropy(db[sha256]["path"]) ## Check file entropy (>9 sounds bad)
        VTScan = VTcheck.getVTScore(sha256) #launch Virustotal scan
        logger.info("Entropy is ;%s",db[sha256]["entropy"])
        if VTScan["positives"] != 0:
            db[sha256]["virustotal"] = VTScan["positives"]
            db[sha256]["permalink"] = VTScan["permalink"]
            logger.info("Virustotal results ;%s",VTScan)
            WebHook("virustotal",sha256,db[sha256])
        if ha_scan and ha_scan[0]["verdict"] == "malicious":
            db[sha256]["hybrid-analysis"] = ha_scan[0]["verdict"]
            logger.info("Hybrid Analysis results ;%s",ha_scan)
            WebHook("hybrid-analysis",ha_scan[0]["sha256"],ha_scan[0])
        time.sleep(int(config.parse["virustotal"]['wait'])) #wait for API restrictition

    logger.info("USB-Sanatyzer results ; %s",db)
    ####### END Check #######


