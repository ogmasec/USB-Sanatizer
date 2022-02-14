'''
Author : mathieu.guerin@ogmasec.fr



'''
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import private.config as config
import logging
import os, errno
logger = logging.getLogger(__name__)

try:
	fh = logging.FileHandler(config.parse['logging']['file'])
except OSError as e:
	if e.errno != errno.EEXIST:
		raise

fh.setLevel(logging.DEBUG)
logging.basicConfig(level=os.environ.get("LOGLEVEL", config.parse['logging']['level']))
formatter = logging.Formatter(config.parse['logging']['format'])
fh.setFormatter(formatter)
logger.addHandler(fh)


