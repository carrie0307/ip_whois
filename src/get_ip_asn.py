#coding=utf-8
from pymongo import *
import get_whois
import time

'''
获取ipasn

暂未添加异常处理和多线程
'''


def main():
    client = MongoClient('172.29.152.152', 27017)
    db = client.ip_whois
    collection = db['ip_asn']
    res = collection.find({'asn':0},{'_id':False, 'ip':True})
    res = list(res)
    counter = 0
    for ip in res:
        ip = ip['ip']
        try:
            asn = get_whois.get_final_asn(ip)
            collection.update({'ip':ip}, {'$set':{'asn':asn}})
            print ip, asn
            # 防止被ban
            counter += 1
            if counter == 1000:
                time.sleep(100)
                counter = 0
        except:
            print '\n' + ip + 'wrong' + '\n'


if __name__ == '__main__':
    main()
