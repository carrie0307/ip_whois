#coding=utf-8
from pymongo import *

'''建立链接'''
client = MongoClient('172.29.152.152', 27017)
db = client.ip_whois
collection = db.ip_whois_test


def insert_whois_record(std_whois_info):
    # try:
    print std_whois_info
    collection.insert(std_whois_info)
    #     return True
    # except:
    #     return False
