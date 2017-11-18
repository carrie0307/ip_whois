#coding=utf-8
import get_whois
import parse_whois
import mongodb_operation

collection = mongodb_operation.mongo_connection()
# 203.98.7.65save 有误

def main():
    global collection
    with open('ip_list.txt', 'r') as f:
        lines = f.readlines()
    ips = []
    for line in lines:
        ip = line.strip()
        ips.append(ip)
    for query_ip in ips:
        # query_ip = raw_input('Input the ip:')
        try:
            asn_registry,ip_whois = get_whois.get_finall_whois(query_ip)
        except:
            print query_ip + 'whois 有误\n'
            continue
        std_whois_info = parse_whois.std_deal_whois(query_ip, asn_registry, ip_whois)
        try:
            collection.insert(std_whois_info)
        except:
            print query_ip + 'save 有误\n'
            continue
        print query_ip + "saved ..."

if __name__ == '__main__':
    main()
