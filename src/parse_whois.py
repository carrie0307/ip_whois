#coding=utf-8
import re
import get_whois
import datetime

# import sys
# reload(sys)
# sys.setdefaultencoding('gbk')

RIR_WHOIS = {
    'arin': {'server': 'whois.arin.net'},
    'lacnic':{'server': 'whois.lacnic.net'},
    'ripe': {'server': 'whois.ripe.net'},
    'apnic': {'server': 'whois.apnic.net'},
    'afrinic': {'server': 'whois.afrinic.net'}
}

def parse_afrinic_whois(asn_registry, whois_info):
    sector_names = []
    field_info = RIR_WHOIS[asn_registry]['fields']
    ip_whois = {}
    ini_whois_info_sector = whois_info.split('\n\n')
    whois_info_sector = []
    for whois_sector in ini_whois_info_sector:
        if '%' not in whois_sector:
            # 由于每一段的最后一行缺少'\n'提取会失败，因此手动添加一个
            sector_name = whois_sector.split(':')[0]
            sector_names.append(sector_name)
            whois_sector += '\n---'
            whois_info_sector.append(whois_sector)
    print sector_names
    for sector,whois_sector in zip(sector_name,whois_info_sector):
        ip_whois[sector] = {}
        for key in RIR_WHOIS[asn_registry]['fields']:
            field_info = RIR_WHOIS[asn_registry]['fields'][key]
            parse_info = re.compile(field_info).findall(whois_sector)
            if key == 'descr':
                print parse_info
            if parse_info: # 如果提取到了相关信息
                if len(parse_info) == 1:
                    ip_whois[sector][key] = parse_info
                else:
                    ip_whois[sector][key] = parse_info
            # else:
                # ip_whois[sector][key] = ''
    # print ip_whois['netinfo'].keys()
    # print ip_whois['person_info'].keys()
    # print ip_whois['route_info'].keys()
    return ip_whois


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
                item_name = line.split(':')[0].strip()
                # regex = item_name + r':[^\S]+(.*)'
                # 把 + 改为 * 说明冒号可以直接和后面data相连没有空格
                regex = item_name + r':[^\S]*(.*)'
                item_value = re.compile(regex,re.I).findall(line)
                '''
                eg. arin-174.139.55.107 存在一个comment内容为空
                Found a referral to vault.krypt.com:4321.提取有误
                '''
                item_value = item_value[0].strip() if item_value else ''
                # if item_value:
                if item_name not in temp.keys():
                    temp[item_name] = item_value
                else:
                    if isinstance(temp[item_name],list):
                        temp[item_name].append(item_value)
                    else:
                        temp[item_name] = [temp[item_name]]
                        temp[item_name].append(item_value)
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
    # afraicnic
    # with open('ipwhois.txt', 'r') as f:
    #     whois_info = f.read()
    # query_ip = '172.16.220.171'
    # asn_registry,whois_info = get_whois.get_finall_whois(query_ip)
    # print asn_registry
    # print whois_info
    whois_info = get_whois.get_whois('223.220.0.0', 'apnic')
    whois_info = parse_whois_info('apnic', whois_info)
    whois_info['insert_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print whois_info
