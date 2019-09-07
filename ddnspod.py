#!/usr/bin/env python3

import sys
import logging
import requests

hdlr = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
hdlr.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


class Dnspod:
    def __init__(self, token, domain_id):
        self.token = token
        self.domain_id = domain_id

        # Get records
        # TODO


    def get_ip(self, domain, rtype='A'):
        # TODO
        pass


    def update_ip(self, domain, rtype='A'):
        # TODO
        pass


def get_ipv4_wan():
    headers = {"User-Agent": "curl/python-requests"}
    r = requests.get('https://ifconfig.co', headers=headers, timeout=20)
    return r.text


def ddns():
    ip = get_ipv4_wan()
    logger.info(f"WAN IP {ip}")


if __name__ == '__main__':
    ddns()
