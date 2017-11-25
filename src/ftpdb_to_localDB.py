#coding=utf-8
from pymongo import *
import re

'''
把ftp获取到的数据库文件导入本地数据库中，先以afrinic为例子

暂定计划按照object进行分表，采用mongo数据库
采用mongo的原因： 1. 每个object实际有哪些字段不能完全确定，mongo可以处理这个
                2. 一些分行的数据可能长度特别长，mongo处理较好
                3. 一个对象内有重复字段，例如，2个admin-c之类（适合mongo）

         问题： 可能不如mysql便于查询

'''


client = MongoClient('172.29.152.152', 27017)
db = client.afrinic_whois_test

def read_file(filepath):
    with open(filepath,'r') as f:
        data = f.read()
    return data


def afrinic_whois_file2db(file_data):
    '''
    解析读取到whoisdb的内容，存入数据库

    目前是以非洲的数据库为例完成

    注： 每个sector即为按照对象划分后每一“段”的内容（避免与object关键词冲突）
        sector_name即为对象名
    '''
    global db

    file_data = file_data.split('\n\n')
    object_names = []

    for sector in file_data: # sector是每一段

        object_dict = {} # 临时存储每一个对象的信息

        '''先对整段进行解析，获得该段第一行的属性名称sector_name'''
        if sector and sector[0] != '#': # 非洲#是注释
            # sector_name = sector.split(': ') # 取第一个冒号分割得到该段的名称
            sector_name = sector.split(':') # 取第一个冒号分割得到该段的名称 注意这里的冒号后是否需要加空格
            if sector_name: # sector_name即是每个对象的名称
                sector_name = sector_name[0].strip()
                '''无表则建立表，有则直接建立连接'''
                currection_collection=db[sector_name + '-db']

            '''对该段的每一行进行解析'''
            items = sector.split('\n') # 得到每一行
            for item in items: # 提取每一行的内容
                # 这里用“冒号加2个空格”来判断,避免是没有实际信息的一行，也避免一个冒号判断时被时间中冒号干扰
                if ':  ' in item:
                    item_name = item.split(':') # 提取属性名
                    if item_name: # 属性名提取不为空，则进一步提取属性值
                        item_name = item_name[0].strip()
                        regex = item_name + r':[^\S]*(.*)' # 提取属性值的正则表达式
                        item_value = re.compile(regex,re.I).findall(item)
                        item_value = item_value[0].strip() if item_value else ''
                        if item_name not in object_dict:
                            object_dict[item_name] = item_value
                        else:
                            if isinstance(object_dict[item_name], list):
                                object_dict[item_name].append(item_value)
                            else:
                                object_dict[item_name] = [object_dict[item_name]]
                                object_dict[item_name].append(item_value)

            currection_collection.insert(object_dict)



if __name__ == '__main__':
    data = read_file('afrinic.db')
    afrinic_whois_file2db(data)
