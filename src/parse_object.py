#coding=utf-8
'''
    解析whois信息中的各个对象，获取查找其他对象的handle
'''

def parse_inetnum_object(inetnum_object):
    '''
    解析inetnum获得admin-c,tech-c,org(目前先获取这些)
    '''
    person_hdl = []
    org = ''

    for key in inetnum_object:
        # 获取admin-c和tech-c  QUESTION:目前inetnum中未发现admin-c和tech-c
        if key == 'admin-c' or key == 'tech-c':
            if not isinstance(inetnum_object[key],list):
                if inetnum_object[key] not in person_hdl:
                    print key + ':', inetnum_object[key]
                    person_hdl.append(inetnum_object[key])
            else: # 有多个admin-c  或 多个tech-c 的情况
                for hdl in inetnum_object[key]:
                    if hdl not in person_hdl:
                        print key + ':', hdl
                        person_hdl.append(hdl)

        if key == 'org': # afrinic是org，尚未确定其他组织是否会是其他写法，如大写Org等，也未发现org有多个的情况
            print 'org:', inetnum_object[key]
            org = inetnum_object[key]

    return person_hdl,org
