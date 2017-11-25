#coding=utf-8

'''
    测试多久时间的访问会被ban
'''

import time
import log
from pymongo import *

client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_asinfo_copy

# server_dict = {'whois.cymru.com':'38.229.36.122'}
# whois.arin.net 199.71.0.46
# whois.arin.net 199.5.26.46
# whois.arin.net 199.212.0.46
#
# whois.lacnic.net 200.3.14.10
#
# whois.ripe.net 193.0.6.135
#
# whois.apnic.net 202.12.29.220
#
# whois.afrinic.net 196.216.2.20
# whois.afrinic.net 196.216.2.21


def socket_connect(query_ip, server):
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect((server, 43))
    # Query the Cymru whois server, and store the results.
    conn.send((
        ' -r -a -c -p -f {0}{1}'.format(
            query_ip, '\r\n')
    ).encode())

    data = ''
    while True:

        d = conn.recv(4096).decode()
        data += d

        if not d:

            break
    return data


def main():
    global collection
    test_ips = collection.find({},{'ip':True,'_id':False})
    test_ips = list(test_ips)
    while True:
        for ip in test_ips:
            try:
                ip = ip['ip']
                start = time.time()
                socket_connect(ip, '38.229.36.122')
            except:
                end = time.time()
                gap = end - start
                log.logger.info("BAN TIME INTERVAL: " + gap)


if __name__ == '__main__':
    log.logger.info("hello")
