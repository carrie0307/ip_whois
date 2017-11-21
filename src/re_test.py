#coding=utf-8
import re

'''
^开头  和 $结尾 的重要性！！！

#ASBLOCK也 匹配wenti

asset怎么找

route105.37.214.20

大于和小于某个数的正则表达式

'''

def hund_test():
    s = '162'
    le_test = '107'
    ge_test = '152'
    # regx = []
    # for j in len(s):
    if int(s) > 99:
        hunds = int(s[0])
        tens = int(s[1])
        units = int(s[2])
        if int(s) > 199:
            le_hunds_regx = ['^[1-' + str(hunds - 1) + '][0-9][0-9]$', '^' + str(hunds) + '[0-' + str(tens - 1) + '][0-9]$', '^' + '[' + str(hunds) + '][' + str(tens) + '][0-' + str(units) + ']$']
        else:
            # 百位为1时，不用考虑其他百位的情况
            le_hunds_regx = ['^' + str(hunds) + '[0-' + str(tens - 1) + '][0-9]$', '^' + '[' + str(hunds) + '][' + str(tens) + '][0-' + str(units) + ']$']
        le_hunds_regx = '|'.join(le_hunds_regx)
        le_regx = '|'.join([r'^[\d]{1,2}$',le_hunds_regx])
        print le_regx
        ge_hunds_regx = ['^[' + str(hunds) + '][' + str(tens) + '][' + str(units) + '-9]$', '^[' + str(hunds) + '][' + str(tens + 1) + '][0-9]$', '^[' + str(hunds + 1) + '-9][0-9][0-9]$']
        ge_regx = '|'.join(ge_hunds_regx)
        le_flag = re.match(le_regx, le_test)
        ge_flag = re.match(ge_regx, ge_test)
        if le_flag:
            print '--ok--'
        if ge_flag:
            print '++ok++'
    elif int(s) > 9:
        tens = int(s[0])
        units = int(s[1])
        # if
        le_tens_regx = ['^[1-' + str(tens - 1) + '][0-9]$', '&[' + str(tens) + '][0-' + str(units)]





def tens_le():
    '''
    小于某十位数
    '''
    s = '37'
    le_test = '32'
    if int(s) > 9:
        tens = int(s[0])
        units = int(s[1])

        if units != 0:
            le_tens_regx = '^[' + str(tens) + '][0-' + str(units) + ']$'
        else:
            le_tens_regx = '^' + str(s) + '$'

        if tens != 1:
            if tens == 2:
                le_tens_regx += '|^1' + '[0-9]$'
            else:
                le_tens_regx += '|^[1-' + str(tens - 1) + '][0-9]$'

        # if int(s) <20:
        #     if int(s) == 10:
        #         le_tens_regx = r'^10$'
        #     else:
        #         le_tens_regx = '^1[0-' + str(units) + ']$'
        # else:
        #     if tens != 2:
        #         le_tens_regx = '^[1-' + str(tens - 1) + '][0-9]$'
        #     else:
        #         le_tens_regx = '^1' + '[0-9]$'
        #     if units != 0:
        #         le_tens_regx += '|^[' + str(tens) + '][0-' + str(units) + ']$'



        le_regx = '|'.join([r'^[\d]{1}$', le_tens_regx])
        le_flag = re.match(le_regx, le_test)
        print le_regx
        if le_flag:
            print '--ok--'






def tens_ge():
    '''
    大于某十位数
    '''
    s = '37'
    ge_test = '120'
    if int(s) > 9:
        tens = int(s[0])
        units = int(s[1])
        if units != 9:
            ge_tens_regx = r'^' + str(tens) + '[' + str(units) + '-9]$'
        else:
            ge_tens_regx = r'^' + str(s) + '$'

        if tens != 9:
            if tens == 8:
                ge_tens_regx += '|' + r'^9' +  '[0-9]$'
            else:
                ge_tens_regx += '|' + r'^['+ str(tens + 1) + '-9]' +  '[0-9]$'

        ge_regx = '|'.join([ge_tens_regx,r'^[\d]{3}$', ])

        ge_flag = re.match(ge_regx, ge_test)
        print ge_regx
        if ge_flag:
            print '++ok++'


if __name__ == '__main__':
    tens_le()
    tens_ge()
