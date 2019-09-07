#!/usr/bin/env python3

import requests

def get_ipv4_wan():
    headers = {"User-Agent": "curl/python-requests"}
    r = requests.get('https://ifconfig.co', headers=headers, timeout=20)
    return r.content.strip()

if __name__ == '__main__':
    ip = get_ipv4_wan()
    print(ip)
