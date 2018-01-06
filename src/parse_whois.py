#coding=utf-8
'''
    功能：将原始的whois信息解析成字典形式

'''
import re
import get_whois
import datetime
import mongodb_operation
# import sys
# reload(sys)
# sys.setdefaultencoding('gbk')


def strip_str(string):
    return string.strip()


def parse_whois_info(asn_registry,whois_info):
    '''
    进行whois原始(socket方式获得的)信息的提取(以对象为单位划分，将属性分别归入对象)
    '''
    # QUESTION: 现在觉得这个写的太繁琐，参考解析ftp数据的改一下
    sector_names = []
    ip_whois = {}
    ini_whois_info_sector = whois_info.split('\n\n')# 分出大的段
    whois_info_sector = []
    for whois_sector in ini_whois_info_sector:
        if '%' not in whois_sector:
            # arin的注释是'#'，但ripe等公司有些内容中包括#(所以arin遇到#就可以不处理？)
            # 这个处理是不是有点问题？？？之后再看
            if asn_registry == 'arin' and '#' in whois_sector:
                continue
            sector_name = whois_sector.split(': ')[0] # 获得每一段第一个字段作为行首名称
            sector_name = sector_name.strip()
            if sector_name:
                sector_names.append(sector_name)
            if whois_sector:
                whois_sector += '\n---'
                whois_info_sector.append(whois_sector)
    for sector,whois_sector in zip(sector_names,whois_info_sector):
        lines = whois_sector.split('\n')
        temp = {} # 临时存储当前一段的内容
        '''以下是对一个object的处理 '''
        for line in lines:

            if line != '---' and line != '':

                ''' r':  +'(两个空格)，为了避免错误提取/Original nic-hdl in AUNIC: DP5-AU/中AUNIC: DP5-AU的部分'''
                temp_split = re.split(r':  +',line)

                #                 Taipei Taiwan 这种情况下line[0] == ' '
                if line[0] != ' ':
                    item_name = temp_split[0].strip()
                    # regex = item_name + r':[^\S]+(.*)'
                    # 把 + 改为 * 说明冒号可以直接和后面data相连没有空格
                    regex = item_name + r':[^\S]*(.*)'
                    item_value = re.compile(regex,re.I).findall(line)
                    '''
                    eg. arin-174.139.55.107 存在一个comment内容为空
                    Found a referral to vault.krypt.com:4321.提取有误
                    '''
                    item_value = item_value[0].strip() if item_value else ''

                    if item_name not in temp.keys():
                        temp[item_name] = item_value
                    else:
                        if isinstance(temp[item_name],list):
                            temp[item_name].append(item_value)
                        else:
                            temp[item_name] = [temp[item_name]]
                            temp[item_name].append(item_value)
                elif line[0] == ' ':
                    item_value = line.strip()
                    if not isinstance(temp[item_name],list):
                        # 此时的item_name还与上一次的相同
                        temp[item_name] = temp[item_name] + ' ' + item_value
                    elif isinstance(temp[item_name],list):
                        '''
                        处理以下情况
                        address: ---
                        address: ###
                                 +++
                        '''
                        length = len(temp[item_name])
                        temp[item_name][length-1] += item_value
                    # print temp[item_name]


        '''将处理好的一个对象的信息，加入到ipwhois信息的字段中'''
        if sector not in ip_whois.keys():
            ip_whois[sector] = temp
        else:
            if isinstance(ip_whois[sector],list):
                ip_whois[sector].append(temp)
            else:
                ip_whois[sector] = [ip_whois[sector]]
                ip_whois[sector].append(temp)
    return ip_whois


def std_deal_whois(query_ip, asn_registry, ip_whois):
    '''
    标准化格式处理
    '''
    std_ip_whois = {}
    std_ip_whois['ip'] = query_ip
    std_ip_whois['asn_registry'] = asn_registry
    whois_info =parse_whois_info(asn_registry,ip_whois)
    std_ip_whois['whois'] = whois_info
    return std_ip_whois



if __name__ == '__main__':
    collection = mongodb_operation.mongo_connection()
    whois_info = get_whois.get_whois('203.11.221.0', 'apnic')
    print whois_info
    # with open('special_whois2.txt','r') as f:
        # whois_info = f.read()
    whois_info = parse_whois_info('apnic', whois_info)
    whois_info['insert_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    collection.insert(whois_info)
    # for key in whois_info['inetnum']:
    #     print key + ':'
    #     print whois_info['inetnum'][key]
    #     print '\n'
    #
    # print whois_info
