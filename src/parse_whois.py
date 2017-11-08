#coding=utf-8
import re
import get_whois
# import sys
# reload(sys)
# sys.setdefaultencoding('gbk')

RIR_WHOIS = {
    'arin': {
        'server': 'whois.arin.net',
        'fields': {
            'name': r'(NetName):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(NetHandle):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(OrgName|CustName):[^\S\n]+(?P<val>.+?)'
                    '(?=(\n\S):?)',
            'country': r'(Country):[^\S\n]+(?P<val>.+?)\n',
            'state': r'(StateProv):[^\S\n]+(?P<val>.+?)\n',
            'city': r'(City):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(Address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'postal_code': r'(PostalCode):[^\S\n]+(?P<val>.+?)\n',
            'emails': (
                r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)('
                '[^\S\n]+.*?)*?\n'
            ),
            'created': r'(RegDate):[^\S\n]+(?P<val>.+?)\n',
            'updated': r'(Updated):[^\S\n]+(?P<val>.+?)\n',
        },
        'dt_format': '%Y-%m-%d'
    },
    'lacnic': {
        'server': 'whois.lacnic.net',
        'fields': {
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'descr': r'(owner):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'emails': (
                r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)('
                '[^\S\n]+.*?)*?\n'
            ),
            'created': r'(created):[^\S\n]+(?P<val>[0-9]{8}).*?\n',
            'updated': r'(changed):[^\S\n]+(?P<val>[0-9]{8}).*?\n'
        },
        'dt_format': '%Y%m%d'
    },
    'ripe': {
        'server': 'whois.ripe.net',
        'fields': {
            # 'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'netrange':r'inetnum:[^\S\n]+(.+?)\n',
            'name': r'netname:[^\S\n]+(.+?)\n',
            'admin-c':r'admin-c:[^\S\n]+(.+?)\n',
            'tech-c':r'tech-c:[^\S\n]+(.+?)\n',
            'status':r'status:[^\S\n]+(.+?)\n',
            'mnt-lower': r'mnt-lower:[^\S\n]+(.+?)\n',
            'mnt-domains': r'mnt-domains:[^\S\n]+(.+?)\n',
            'mnt-routes': r'mnt-routes:[^\S\n]+(.+?)\n',
            'mnt-by':r'mnt-by:[^\S\n]+(.+?)\n',
            'nic-hdl':r'nic-hdl:[^\S\n]+(.+?)\n',
            'remarks': r'remarks:[^\S\n]+(.+?)\n',
            'created': r'created:[^\S\n]+(.+?)\n',
            'created': r'created:[^\S\n]+(.+?)\n',
            'organisation': r'organisation:[^\S\n]+(.+?)\n',
            'org-name': r'org-name:[^\S\n]+(.+?)\n',
            'org-type': r'org-type:[^\S\n]+(.+?)\n',
            'source': r'source:[^\S\n]+(.+?)\n',
            'person': r'person:[^\S\n]+(.+?)\n',
            'address': r'address:[^\S\n]+(.+?)(?=\n\S:?)',
            'phone': r'phone:[^\S\n]+(.+?)\n',
            'route': r'route:[^\S\n]+(.+?)\n',
            # 'handle':r'(nic-hdl):[^\S\n]+(.+?)\n',
            # 'descr':r'descr:[^\S\n]+(.+?)(?=(\n\S):?)',
            'descr':r'descr:[^\S\n]+(.+?)\n',
            'country':r'(country):[^\S\n]+(.+?)\n',
            'address':r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
        },
        'dt_format': '%Y-%m-%dT%H:%M:%SZ'
    },
    'apnic': {
        'server': 'whois.apnic.net',
        'fields': {
            'netrange':r'inetnum:[^\S\n]+(.+?)\n',
            'name': r'netname:[^\S\n]+(.+?)\n',
            'nic-hdl': r'nic-hdl:[^\S\n]+(.+?)\n',
            'admin-c': r'admin-c:[^\S\n]+(.+?)\n',
            'tech-c': r'tech-c:[^\S\n]+(.+?)\n',
            'mnt-by': r'mnt-by:[^\S\n]+(.+?)\n',
            'status': r'status:[^\S\n]+(.+?)\n',
            'source': r'source:[^\S\n]+(.+?)\n',
            'last-modified': r'last-modified:[^\S\n]+(.+?)\n',
            'person': r'person:[^\S\n]+(.+?)\n',
            'route': r'route:[^\S\n]+(.+?)\n',
            'email': r'e-mail:[^\S\n]+(.+?)\n',
            'phone': r'phone:[^\S\n]+(.+?)\n',
            'fax': r'fax-no:[^\S\n]+(.+?)\n',
            'description': r'descr:[^\S\n]+(.+?)(?=\n\S:?)',
            'country': r'country:[^\S\n]+(.+?)\n',
            # 'address': r'address:[^\S\n]+(.+?)(?=\n\S:?)',
            'address': r'address:[^\S\n]+(.+?)\n',
            # 'updated': r'last-modified:[^\S\n]+.*(?P<val>[0-9]{8}).*?\n',
            'origin': r'origin:[^\S\n]+(.+?)\n',
        },
        'dt_format': '%Y%m%d'
    },
    'afrinic': {
        'server': 'whois.afrinic.net',
        'fields': {
            # 'netrange':r'(inetnum):[^\S\n]+(?P<val>.+?)\n',
            'netrange':r'inetnum:[^\S\n]+(.+?)\n',
            'name': r'netname:[^\S\n]+(.+?)\n',
            'descr': r'descr:[^\S\n]+(.+?)(?=\n\S:?)',
            'country': r'country:[^\S\n]+(.+?)\n',
            'admin-c': r'admin-c:[^\S\n]+(.+?)\n',
            'tech-c': r'tech-c:[^\S\n]+(.+?)\n',
            'status': r'status:[^\S\n]+(.+?)\n',
            'mnt-by': r'mnt-by:[^\S\n]+(.+?)\n',
            'source': r'source:[^\S\n]+(.+?)\n',
            'parent': r'parent:[^\S\n]+(.+?)\n',
            'person': r'person:[^\S\n]+(.+?)\n',
            'nic-hdl': r'nic-hdl:[^\S\n]+(.+?)\n',
            'phone': r'phone:[^\S\n]+(.+?)\n',
            'route': r'route:[^\S\n]+(.+?)\n',
            'remarks': r'remarks:[^\S\n]+(.+?)\n',
            'origin': r'origin:[^\S\n]+(.+?)\n',
            'address': r'address:[^\S\n]+(.+?)(?=\n\S:?)',
            # 'address': r'address:[^\S\n]+(.+?)(?=(\n\S):?)',
        }
    }
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


# def parse_whois(whois_info):
#     '''
#     ripe ok
#
#     '''
#     sector_names = []
#     ip_whois = {}
#     ini_whois_info_sector = whois_info.split('\n\n')
#     whois_info_sector = []
#     for whois_sector in ini_whois_info_sector:
#         # arin 中注释是 #
#         if '%' not in whois_sector and '#' not in whois_sector:
#             sector_name = whois_sector.split(': ')[0]
#             sector_name = sector_name.strip()
#             sector_names.append(sector_name)
#             whois_info_sector.append(whois_sector)
#     for sector,whois_sector in zip(sector_names,whois_info_sector):
#         # 注意冒号后面一定要有空格，避免把时间分割开
#         items = re.split(r': |\n', whois_sector)
#         ip_whois[sector] = {}
#         for i in range(0, len(items), 2):
#             key = items[i].strip()
#             if key == '':
#                 continue
#             # print sector, key
#             value = items[i + 1].strip()
#             if key not in ip_whois[sector].keys():
#                 ip_whois[sector][key] = value
#             else:
#                 if isinstance(ip_whois[sector][key],list):
#                     ip_whois[sector][key].append(value)
#                 else:
#                     ip_whois[sector][key] = [ip_whois[sector][key]]
#                     ip_whois[sector][key].append(value)
        # print ip_whois[sector].keys()
    # print items
    # for rir in ip_whois:
    #     print rir
    #     for key in ip_whois[rir]:
    #         print key, ip_whois[rir][key]
    #     print '\n'
    # print sector_names


# def parse_whois_test(whois_info):
#     '''
#     ripe ok
#
#     '''
#     sector_names = []
#     ip_whois = {}
#     ini_whois_info_sector = whois_info.split('\n\n')
#     whois_info_sector = []
#     for whois_sector in ini_whois_info_sector:
#         # arin 中注释是 #
#         if '%' not in whois_sector and '#' not in whois_sector:
#             sector_name = whois_sector.split(': ')[0]
#             sector_name = sector_name.strip()
#             sector_names.append(sector_name)
#             whois_info_sector.append(whois_sector)
#     for sector,whois_sector in zip(sector_names,whois_info_sector):
#         # 注意冒号后面一定要有空格，避免把时间分割开
#         # print whois_sector
#         items = re.split(r': |\n', whois_sector)
#         # print items
#         ip_whois[sector] = {}
#         i = 0
#         # print items
#         while i < len(items):
#             if items[i] == '':
#                 i += 1
#                 continue
#             key = items[i].strip()
#             print key, str(i)
#             value = items[i + 1].strip()
#             if key not in ip_whois[sector].keys():
#                 ip_whois[sector][key] = value
#             else:
#                 if isinstance(ip_whois[sector][key],list):
#                     ip_whois[sector][key].append(value)
#                 else:
#                     ip_whois[sector][key] = [ip_whois[sector][key]]
#                     ip_whois[sector][key].append(value)
#             i += 2
#     # for rir in ip_whois:
#     #     print rir + ":"
#     #     for key in ip_whois[rir]:
#     #         print key, ip_whois[rir][key]
#     #     print '\n'
#     # print sector_names


def parse_whois_info(asn_registry,whois_info):
    '''
    进行whois原始信息的提取
    '''
    sector_names = []
    ip_whois = {}
    ini_whois_info_sector = whois_info.split('\n\n')# 分出大的段
    whois_info_sector = []
    for whois_sector in ini_whois_info_sector:
        if '%' not in whois_sector:
            # arin的注释是'#'，但ripe等公司有些内容中包括#
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
    with open('ipwhois.txt', 'r') as f:
        whois_info = f.read()
    print parse_whois_info('ripencc',whois_info)
