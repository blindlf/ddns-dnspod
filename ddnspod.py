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
        data = {"login_token": token, "format": "json", "domain_id": domain_id}
        r = requests.post("https://dnsapi.cn/Record.List", data = data)
        self.records = r.json()


    def _find(self, domain, rtype):
        for r in self.records["records"]:
            if domain == r["name"] and rtype == r["type"]:
                return r
        return None


    def get(self, domain, rtype='A'):
        r = self._find(domain, rtype)
        if not r:
            return
        return r["value"]


    def update(self, domain, rtype='A'):
        # TODO
        pass


def get_wan_ipv4():
    headers = {"User-Agent": "curl/python-requests"}
    r = requests.get('https://ifconfig.co', headers=headers, timeout=20)
    return r.text.strip()


def ddns(token, domain_id):
    dnspod = Dnspod(token, domain_id)
    logger.info("DNSPOD")
    logger.info(dnspod.records)
    ipdns = dnspod.get("@")

    ipwan = get_wan_ipv4()

    if ipdns != ipwan:
        logger.info(f"IP is changed from {ipdns} to {ipwan}")
        dnspod.update("@", ipwan)
    else:
        logger.info(f"IP unchanged {ipwan}")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ddnspod.py <TOKEN> <DOMAIN_ID>", file=sys.stderr)
        exit(1)
    token = sys.argv[1]
    domain_id = sys.argv[2]
    ddns(token, domain_id)

