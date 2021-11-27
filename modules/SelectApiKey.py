#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import logging

#logging.basicConfig(filename='/home/mathieuguerin/scripting/enrichment/threatgrid/send_object.log',level=logging.DEBUG)
logging.basicConfig(format='[%(levelname)s]%(asctime)s -> %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p',level=logging.DEBUG)

class SelectApiKey:
    """This class allow to select an API key from a file in configuration given in argument"""
    def __init__(self,api_file):
        self.api_file=api_file
        self._api_key=None
        logging.info('Classe "SelectApiKey" called with api_file = "'+api_file+'"')
    def _get_api_key(self):
        """Accesseur Provide the API key from the conf file"""
        logging.debug('Accessor "_get_api_key" called')
        if self._api_key is None:
            logging.error('No API key selected')
            sys.exit()
        else:
            return self._api_key
    def _set_api_key(self,api_name):
        """Mutator Allow to modify the API Key"""
        logging.debug('Mutator "_set_api_key" called for API = "'+api_name+'"')
        self.api_name=api_name
        try:
            file = open(self.api_file, "r")
            logging.info('File "'+self.api_file+'" open')
        except IOError:
            logging.error('File "'+self.api_file+'" not open')
            sys.exit()
        for line in file:
            line = line.strip()
            result=line.split(":")
            if result[0] == self.api_name:
                self._api_key = result[1]
        file.close()
        logging.info('API key "'+self.api_file+':'+self._api_key+'" selected')
    api_key = property(_get_api_key,_set_api_key)
