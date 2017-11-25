#coding=utf-8

'''
    测试多久时间的访问会被ban
'''

import get_whois
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


def main():
    global collection
    test_ips = collection.find({'asn':0},{'ip':True,'_id':False})
    test_ips = list(test_ips)
    flag = True
    counter = 0
    for ip in test_ips:
        try:
            ip = ip['ip']
            normal_start = time.time()
            as_info = get_whois.get_all_asinfo(ip)
            counter += 1 # 计数获取到的数量
            if not flag: # 说明之前被ban，现在恢复正常
                ban_end = time.time()
                ban_gap = ban_end - ban_start
                # 被ban的时间间隔
                log.logger.info("BAN TIME INTERVAL: " + str(ban_gap))
                flag = True
        except Exception,e:
            # BANNED：Connection reset by peer 
            if flag:# 说明之前是正常运行的，开始被ban
                normal_end = time.time()
                # 允许正常运行的时间间隔
                normal_gap = normal_end - normal_start
                log.logger.info("Normal Perios : " + str(normal_gap) + '\n获取到as信息: ' + str(counter) + '\nerror: ' + str(e))
                flag = False
                counter = 0
                ban_start = time.time()
                continue
            else:
                continue
                # 说明始终处于被ban的状态
        try:
            collection.update({'ip':ip}, {'$set':{
                                        'asn_country_code':as_info['asn_country_code'],
                                         'rir':as_info['rir'],
                                         'asn_date':as_info['asn_date'],
                                         'asn_cidr':as_info['asn_cidr'],
                                         'asn':as_info['asn'],
                                         'asn_description':as_info['asn_description']
                                         }})
            print ip + 'saved ... '
        except:
            print '存储有误...'
            continue



if __name__ == '__main__':
    main()
