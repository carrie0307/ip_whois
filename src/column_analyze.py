#coding=utf-8
import re
import mongodb_operation
import os

collection = mongodb_operation.mongo_connection()


rirs = ['arin', 'ripencc', 'apnic', 'afrinic', 'lacnic']


def count_rir():
    '''
    统计表中每个rir对应的ip数量

    arin 231
    ripencc 445
    apnic 468
    afrinic 446
    lacnic 447

    '''
    global collection
    for asn_registry in rirs:
        res = collection.find({},{'domain': True, '_id':False, 'domains_reg':True})
        print asn_registry, collection.find({'asn_registry':asn_registry}).count()

def lacnic_count():
    global collection
    res = collection.find({'asn_registry':'lacnic'},{'whois': True, '_id':False})
    res = list(res)
    for item in res:
        if item["whois"].keys() != [u'nic-hdl-br', u'inetnum']:
            print item["whois"].keys()


def read_file(filepath):
    with open(filepath,'r') as f:
        data = f.read()
    return data




def afrinic_get_sector_names(file_data):
    # afrinic的as-block中的remarks内容总是有换行
    whois_columns = {}
    sector_names = []
    file_data = file_data.split('\n\n')

    for sector in file_data: # sector是每一段
        if sector and sector[0] != '#': # 非洲#是注释
            # sector_name = sector.split(': ') # 取第一个冒号分割得到该段的名称
            sector_name = sector.split(':') # 取第一个冒号分割得到该段的名称 注意这里的冒号后是否需要加空格
            if sector_name:
                sector_name = sector_name[0].strip()
                if sector_name not in whois_columns:
                    whois_columns[sector_name] = []
            items = sector.split('\n') # 得到每一行
            for item in items: # 提取每一行的内容
                if ': ' in item:
                    # print item
                    item_name = item.split(':')
                    if item_name: # remarks多行，有的
                        item_name = item_name[0].strip()
                        if item_name not in whois_columns[sector_name]:
                            # print item_name
                            whois_columns[sector_name].append(item_name)



    for sector_name in whois_columns:
        print sector_name
        for column in whois_columns[sector_name]:
            print column + ',',
        print '\n'

    return sector_names


# 遍历指定目录，显示目录下的所有文件名
def eachFile(filepath):
    filelist = []
    pathDir =  os.listdir(filepath)
    for allDir in pathDir:
        child = os.path.join('%s%s' % (filepath, allDir))
        filelist.append(child)
    return filelist
        # print child.decode('gbk') # .decode('gbk')是解决中文显示乱码问题




if __name__ == '__main__':
    # file_list = eachFile('../src/apnic/')
    # for filepath in file_list:
    #     data = read_file(filepath)
    #``     sector_names = afrinic_get_sector_names(data)
    # data = read_file('arin.db')
    # afrinic_get_sector_names(data)
    # ss = 'route6:	        2400:cb00:48::/48'
    # for i in ss:
    #     print i
    lacnic_count()
