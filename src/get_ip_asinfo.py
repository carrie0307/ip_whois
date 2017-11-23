#coding=utf-8
from pymongo import *
import get_whois
import time

'''
获取ip的asn信息，整体解析后进行存储

暂未添加异常处理和多线程
'''



def main():
    client = MongoClient('172.29.152.152', 27017)
    db = client.ip_whois
    collection = db['ip_asinfo2']
    res = collection.find({'asn':0},{'_id':False, 'ip':True})
    res = list(res)
    counter = 0
    for ip in res:
        ip = ip['ip']
        try:
            as_info = get_whois.get_all_asinfo(ip)
            collection.update({'ip':ip}, {'$set':{
                                        'asn_country_code':as_info['asn_country_code'],
                                         'rir':as_info['rir'],
                                         'asn_date':as_info['asn_date'],
                                         'asn_cidr':as_info['asn_cidr'],
                                         'asn':as_info['asn'],
                                         'asn_description':as_info['asn_description']
                                         }})
            print ip + ' saved ...'
            # 防止被ban
            counter += 1
            if counter == 1000:
                time.sleep(100)
                counter = 0
        except:
            print '\n' + ip + 'wrong' + '\n'


if __name__ == '__main__':
    main()
