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

        self.base_url = "https://dnsapi.cn"
        self.headers = {
                "Content-type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
                "User-Agent": "iosapk-ddns/2.1.0 (blindlf@hotmail.com)"
        }

        # Get records
        data = {"login_token": token, "format": "json", "domain_id": domain_id}
        r = requests.post(self.base_url + "/Record.List",
                data = data, headers = self.headers)
        self.records = r.json()


    def _find(self, domain, rtype):
        for r in self.records["records"]:
            if domain == r["name"] and rtype == r["type"]:
                return r
        return None


    def get(self, domain, rtype='A'):
        r = self._find(domain, rtype)
        if not r:
            return None
        return r["value"]


    def update(self, domain, ip, rtype='A'):
        r = self._find(domain, rtype)
        if not r:
            return 0
        data = {
                "login_token": token,
                "format": "json",
                "domain_id": domain_id,
                "record_id": r["id"],
                "sub_domain": domain,
                "value": ip,
                "record_type": rtype,
                "record_line": "默认"
        }
        r = requests.post(self.base_url + "/Record.Modify",
                data = data, headers = self.headers)
        status = r.json()
        code = status["status"]["code"]
        if "1" == code:
            return 0
        logger.error(f"DNS modify error {status}")
        return int(code)


def _get_wan_ip(family='ipv4'):
    import socket
    import requests
    import requests.packages.urllib3.util.connection as urllib3_cn
    family_pre = urllib3_cn.allowed_gai_family

    if family == 'ipv4':
        urllib3_cn.allowed_gai_family = lambda: socket.AF_INET
    else:
        urllib3_cn.allowed_gai_family = lambda: socket.AF_INET6

    headers = {"User-Agent": "curl/python-requests"}
    r = requests.get('https://icanhazip.com', headers=headers, timeout=20)

    urllib3_cn.allowed_gai_family = family_pre
    return r.text.strip()

def get_wan_ipv4():
    return _get_wan_ip('ipv4')

def get_wan_ipv6():
    return _get_wan_ip('ipv6')

def ddns(token, domain_id):
    wanip4 = get_wan_ipv4()
    wanip6 = get_wan_ipv6()

    dnspod = Dnspod(token, domain_id)
    logger.info(f"DNSPOD List: {dnspod.records}")

    code = 0

    def upchg(ip_current, rtype):
        type_name = {'A': 'IPv4', 'AAAA': 'IPv6', 'MX': 'Mail'}
        name = type_name.get(rtype, rtype)

        dns_name = '@'
        ip_dns = dnspod.get(dns_name, rtype)

        if ip_dns != ip_current:
            logger.info(f"{name} is changed from {ip_dns} to {ip_current}")
            return dnspod.update(dns_name, ip_current, rtype)
        else:
            logger.info(f"{name} unchanged {ip_current}")
            return 0

    code |= upchg(wanip4, 'A')
    code |= upchg(wanip6, 'AAAA')
    # code |= upchg('iosapk.net.', 'MX')

    return code


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ddnspod.py <TOKEN> <DOMAIN_ID>", file=sys.stderr)
        exit(1)
    token = sys.argv[1]
    domain_id = sys.argv[2]
    exit(ddns(token, domain_id))
