#coding=utf-8

'''
    测试多久时间的访问会被ban
'''

import get_whois
import time
import log_whois
from pymongo import *

client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_asinfo_copy

server_dict = {
                'arin':'199.71.0.46',
                'apnic':'202.12.29.220',
                'lacnic':'200.3.14.10',
                'ripencc':'193.0.6.135',
                'afrinic':'196.216.2.20'
            }

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


def main():
    global collection
    rir = 'apnic'
    test_ips = collection.find({'rir':rir},{'ip':True,'_id':False})
    test_ips = list(test_ips)
    flag = True
    counter = 0
    for ip in test_ips:
        try:
            ip = ip['ip']
            # normal_start = time.time()
            whois_info = get_whois.get_whois(ip,rir)
            counter += 1 # 计数获取到的数量
            print ip + 'got ...'
            '''说明之前被ban，现在恢复正常'''
            if not flag:
                # 被ban的时间间隔
                # ban_end = time.time()
                # ban_gap = ban_end - ban_start
                log_whois.logger.info("BEGIN RUNNING, ... ")
                flag = True
        except Exception,e:
            '''说明之前是正常运行的，开始被ban'''
            if flag:
                # 允许正常运行的时间间隔
                # normal_end = time.time()
                # normal_gap = normal_end - normal_start
                log_whois.logger.info('BE BANNED,  获取到whois信息: ' + str(counter) + '\nerror: ' + str(e))
                flag = False
                counter = 0
                # ban_start = time.time()
                continue
            else:
                '''说明始终处于被ban的状态'''
                continue



if __name__ == '__main__':
    main()
