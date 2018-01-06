#coding=utf-8
'''
    多线程测试多久会被ban

    每次运行前注意修改 rir 和 thread_num 以及 socket_get_info中 函数

'''
import get_whois
import parse_whois
import threading
import Queue
import mongodb_operation
import datetime
import re
from log import logger

collection = mongodb_operation.mongo_connection()

'''同步队列'''
inetnum_queue = Queue.Queue()
res_queue = Queue.Queue() # 具体要执行的sql语句以及线程号

'''线程数量'''
thread_num = 10

'''具体处理rir'''
rir = 'apnic'



def get_ip():
    '''
    获取要运行的ip加入队列inetnum_queue
    '''
    global inetnum_queue
    # with open('ip_list.txt', 'r') as f:
    # TODO:这里日后应当改为读取inetnum.db的情况
    with open('apnic_inetnum.txt', 'r') as f:
        lines = f.readlines()
    for line in lines:
        inetnum = re.compile('inetnum:        (.+)').findall(line)[0]
        inetnum_queue.put(inetnum)


def socket_get_info():
    '''
    这里具体调用获取信息的函数，返回对应的sql语句
    '''
    global rir
    global inetnum_queue
    global res_queue

    while not inetnum_queue.empty():

        inetnum = inetnum_queue.get()
        try:
            # '''获取whois信息'''
            ip = inetnum.split('-')[0]
            ip = ip.strip()
            whois_info = get_whois.get_whois(ip, rir)
            std_whois = parse_whois.parse_whois_info('apnic', whois_info)
            std_whois['id_inetnum'] = inetnum # 把这个作为查询的id
            std_whois['insert_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            res_queue.put([inetnum,std_whois])
        except Exception,e:
            # 异常的ip重新获取一次
            inetnum_queue.put(inetnum)
            logger.info(inetnum)
            continue
    print 'ip 全部运行完成... '


def whois_info_save():
    '''
    向mongo数据库存储结果
    '''
    global res_queue
    global inetnum_queue
    global collection

    while True:
        try:
            inetnum,std_whois = res_queue.get(timeout=600)
        except:
            print 'all res saved ...'
            break
        try:
            collection.insert(std_whois)
        except:
            # 异常的ip重新获取一次
            inetnum_queue.put(inetnum)
            logger.info(inetnum)
    print 'save over ...'




def main():
    get_ip()
    print "开始获取信息... "
    socket_td = []
    for i in range(thread_num):
        socket_td.append(threading.Thread(target=socket_get_info))
    for td in socket_td:
        td.start()
    print "开始存储结果\n"
    save_res = threading.Thread(target=whois_info_save)
    save_res.start()
    save_res.join()


if __name__ == '__main__':
    main()
