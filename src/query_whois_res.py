#coding=utf-8
from pymongo import *

'''
    在本地数据库进行ipwhois新的查询(主要时各个对象的聚合)

'''
import re

client = MongoClient('172.29.152.152', 27017)
db = client.afrinic_whois_test


def find_route():
    '''
    根据ip查询到route
    '''


def find_person():
    '''
    根据inetnum中的admin-c tech-c 以及 person中的nic-hdl ，找到合适的person对象
    '''



def find_inetnum(query_ip):
    '''
    根据ip查询inetnum(关键是找到合适的ip段)

    eg. 105.37.214.20

    105.37.214.×××    匹配×××最接近20的范围，若匹配不到，则见下

    105.37.×××.---    匹配×××最接近214的范围，若匹配不到，则见下

    105.×××.---.---   匹配×××最接近37的范围，若匹配不到，则见下
    '''
    global db
    collection = db['inetnum-db']
    ip_pattern = query_ip.split('.')
    for i in range(3,-1,-1):

        std_num = str(ip_pattern[i]) # '×××'中要匹配的数字
        ip_pattern[i] = r'[0-9]{1,3}'

        le_ip_pattern = ip_pattern[:]
        le_ip_regex = '.'.join(le_ip_pattern)

        ge_ip_pattern = ip_pattern[:]
        ge_ip_regex = '.'.join(ge_ip_pattern)

        ip_regex = ' - '.join([le_ip_regex, ge_ip_regex])
        # print ip_regex

        res = collection.find({'inetnum':{'$regex':ip_regex}},{'_id':False, 'inetnum':True})
        if res.count() != 0:

            min_distance = 255

            for item in res:

                # 网段左侧部分的匹配
                le_inetnum = item["inetnum"].split(' - ')[0]
                le_match_num = le_inetnum.split('.')[i]
                # TODO 获取std_num的le正则表达式
                le_flag = re.match(r'^[\d]{1}$|^[3][0-7]$|^[1-2][0-9]$',le_match_num)

                # 网段右侧部分的匹配
                ge_inetnum = item["inetnum"].split(' - ')[1]
                ge_match_num = ge_inetnum.split('.')[i]
                # TODO 获取std_num的ge正则表达式
                ge_flag = re.match('^3[7-9]$|^[4-9][0-9]$|^[\d]{3}$',ge_match_num)

                if ge_flag and le_flag:
                    # 通过差找出最接近当前std_num的范围
                    if int(ge_match_num) - int(le_match_num) <= min_distance:
                        current_inetnum = item['inetnum']


            print current_inetnum # TODO 根据inetnum再获取整个inetbum对象
            # 不再进行新的查找
            break





if __name__ == '__main__':
    find_inetnum('105.37.214.20')
