#coding=utf-8
'''
测试：通过socket获取ip的whois信息

注：  用来测试的最基本的代码，未考虑异常处理等内容
'''
import socket
import re
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
            'description': r'(owner):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
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
    'ripencc': {
        'server': 'whois.ripe.net',
        'fields': {
            # 'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'name': r'netname:[^\S\n]+(.+?)\n',
            'admin-c':r'admin-c:[^\S\n]+(.+?)\n',
            'tech-c':r'tech-c:[^\S\n]+(.+?)\n',
            'status':r'status:[^\S\n]+(.+?)\n',
            'mnt-by':r'mnt-by:[^\S\n]+(.+?)\n',
            'nic-hdl':r'nic-hdl:[^\S\n]+(.+?)\n',
            # 'handle':r'(nic-hdl):[^\S\n]+(.+?)\n',
            'description':r'descr:[^\S\n]+(.+?)(?=(\n\S):?)',
            'country':r'(country):[^\S\n]+(?P<val>.+?)\n',
            'address':r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'emails':(
                r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)('
                '[^\S\n]+.*?)*?\n'
            ),
            'created':(
                r'(created):[^\S\n]+(?P<val>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]'
                '{2}:[0-9]{2}:[0-9]{2}Z).*?\n'
            ),
            'updated':(
                r'(last-modified):[^\S\n]+(?P<val>[0-9]{4}-[0-9]{2}-[0-9]{2}T'
                '[0-9]{2}:[0-9]{2}:[0-9]{2}Z).*?\n'
            )
        },
        'dt_format': '%Y-%m-%dT%H:%M:%SZ'
    },
    'apnic': {
        'server': 'whois.apnic.net',
        'fields': {
            'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(descr):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'emails': (
                r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)('
                '[^\S\n]+.*?)*?\n'
            ),
            'updated': r'(changed):[^\S\n]+.*(?P<val>[0-9]{8}).*?\n'
        },
        'dt_format': '%Y%m%d'
    },
    'afrinic': {
        'server': 'whois.afrinic.net',
        'fields': {
            'name': r'(netname):[^\S\n]+(?P<val>.+?)\n',
            'handle': r'(nic-hdl):[^\S\n]+(?P<val>.+?)\n',
            'description': r'(descr):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'country': r'(country):[^\S\n]+(?P<val>.+?)\n',
            'address': r'(address):[^\S\n]+(?P<val>.+?)(?=(\n\S):?)',
            'emails': (
                r'.+?:.*?[^\S\n]+(?P<val>[\w\-\.]+?@[\w\-\.]+\.[\w\-]+)('
                '[^\S\n]+.*?)*?\n'
            ),
        }
    }
}


def get_asn_whois(query_ip):
    '''
    功能： 向whois.cymru.com发出查询，获得ip的AS、ASNAME和管理组织名称asn_registry

    return:返回对应的rip
    '''
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect(('whois.cymru.com', 43))
    # Query the Cymru whois server, and store the results.
    conn.send((
        ' -r -a -c -p -f {0}{1}'.format(
            query_ip, '\r\n')
    ).encode())

    data = ''
    while True:

        d = conn.recv(4096).decode()
        data += d

        if not d:

            break
    print data
    data = data.split('|')
    asn_registry = data[4].strip() # 获取管理组织名称
    return asn_registry



def get_asn_origin_whois(asn):
    ASN_ORIGIN_WHOIS = {
        'radb': {
            'server': 'whois.radb.net',
            'fields': {
                'description': r'(descr):[^\S\n]+(?P<val>.+?)\n',
                'maintainer': r'(mnt-by):[^\S\n]+(?P<val>.+?)\n',
                'updated': r'(changed):[^\S\n]+(?P<val>.+?)\n',
                'source': r'(source):[^\S\n]+(?P<val>.+?)\n',
            }
        },
    }
    # radb是什么？
    server = ASN_ORIGIN_WHOIS['radb']['server']
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    # log.debug('ASN origin WHOIS query for {0} at {1}:{2}'.format(4808, server, 43))
    conn.connect((server, 43))
    query = ' -i origin {0}{1}'.format(asn, '\r\n')

                # Query the whois server, and store the results.
    conn.send(query.encode())

    response = ''
    while True:

        d = conn.recv(4096).decode()

        response += d

        if not d:

            break

    # print response
    # w_file = open('asn_response.txt','w')
    # w_file.write(response)
    # w_file.close()
    conn.close()


def get_whois(query_ip,asn_registry):
    '''
    功能： 根据asn_registry，获取query_ip的whois信息

    return： 返回查询所得的whois信息

    '''
    global RIR_WHOIS

    server = RIR_WHOIS[asn_registry]['server']
    # Create the connection for the whois query.
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(5)
    conn.connect((server, 43))
    # Prep the query.
    query = query_ip + '\r\n'
    # if asn_registry == 'arin':
        # query = 'n + {0}'.format(query)
    # Query the whois server, and store the results.
    conn.send(query.encode())
    response = ''
    while True:
        d = conn.recv(4096).decode('ascii', 'ignore')
        response += d
        if not d:
            break
    conn.close()
    return response


def get_finall_whois(query_ip):
    '''
    获取原始的whois信息
    '''
    asn_registry = get_asn_whois(query_ip)
    whois_info = get_whois(query_ip, asn_registry)
    return asn_registry,whois_info

if __name__ == '__main__':
    # 154.72.28.1
    whois = get_finall_whois('173.234.162.98')
    print whois
    # with open('ipwhois.txt', 'w') as f:
        # f.write(whois)
