import requests
import random
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from concurrent.futures import ThreadPoolExecutor
from proxy import ProxyManager
from mysql import PyMySQLDatabase
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import threading
import queue


class IPInfo:
    def __init__(self):
        self.ip_queue = queue.Queue()
        self.session = requests.session()
        retry_strategy = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        #self.valid_proxy = self.proxy_module.get_valid_proxy()
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.proxy_module = PyMySQLDatabase()
        self.USER_AGENTS = [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.71 Safari/537.1 LBBROWSER",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.84 Safari/535.11 LBBROWSER",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/5.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
            "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Trident/4.0; SV1; QQDownload 732; .NET4.0C; .NET4.0E; 360SE)",
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; QQDownload 732; .NET4.0C; .NET4.0E)",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.1 (KHTML, like Gecko) Chrome/21.0.1180.89 Safari/537.1",
            "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
            "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:2.0b13pre) Gecko/20110307 Firefox/4.0b13pre",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:16.0) Gecko/20100101 Firefox/16.0",
            "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.64 Safari/537.11",
            "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
            ]
        self.query_ip = ''
        self.url = "https://www.venuseye.com.cn:443/ve/ip/ioc"
        #self.cookies = {"temOff": "true",  "kip": {"key1": "value1"}}#,"Hm_lvt_efa6afa67fd33f485307e3a8f373bbb4": "1688695346",  "uid": "c43f5ceedf4051bf1fb1d4392229ade7cc924fd06c02c1f7a7d2b7f376a1e36b", "userKey": "185****8110", "userId": "14624"
        self.cookies = {"temOff": "true", "kip": {"key1": "value1"}}
        self.headers = {"Connection": "close", "Pragma": "no-cache", "Cache-Control": "no-cache", "sec-ch-ua": "\"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"114\", \"Google Chrome\";v=\"114\"", "Accept": "application/json, text/javascript, */*; q=0.01", "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8", "X-Requested-With": "XMLHttpRequest", "sec-ch-ua-mobile": "?0", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36", "sec-ch-ua-platform": "\"Windows\"", "Origin": "https://www.venuseye.com.cn", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Referer": "https://www.venuseye.com.cn/ip/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9"}

    def make_requests(self, urls):
        query_ips = [(url[0], url[2], url[3], url[4], url[1]) for url in urls if url]
        for query_ip in query_ips:
            self.ip_queue.put(query_ip)
        while not self.ip_queue.empty():
            query_ip = self.ip_queue.get()
            self.executor.submit(self.get_ip_info, query_ip)
    def get_ip_info(self,query_ip):
        group = query_ip[0]
        intranetIp = query_ip[1]
        extranetIp = query_ip[2]
        log = query_ip[3]
        standardTimestamp = query_ip[4]
        headers = self.headers.copy()
        headers["User-Agent"] = random.choice(self.USER_AGENTS)
        data = {"target": extranetIp}
        self.cookies["kip"] = extranetIp
        if self.proxy_module.select_data_bjos(extranetIp):
            ip = self.proxy_module.select_data_bjos(extranetIp).get('ip')
            update_time = self.proxy_module.select_data_bjos(extranetIp).get('intelligence')
            threat_score = '99'
            categories = '未知'
            self.proxy_module.insert_data_all(group,intranetIp, ip, threat_score, categories, update_time,log,standardTimestamp)
            print(f'已存在的情报在bjos：{ip}')
        elif not self.proxy_module.select_data(extranetIp): #没有查到
            while True:
                proxies = {
                    "http": "http://u1831004024026219:h8G3OU7IBeJc@54.174.101.70:36923",
                    "https": "http://u1831004024026219:h8G3OU7IBeJc@54.174.101.70:36923"
                }
                try:
                    response = self.session.post(self.url, headers=headers, cookies=self.cookies, data=data,
                                                 verify=False,
                                                 proxies=proxies, timeout=5)
                    if response.json()["status_code"] == 200:
                        result = response.json().get("data", {})
                        ip = result.get("ip")
                        ioc = result.get("ioc", [0])
                        if ioc[0].get("categories", ""):
                            threat_score = ioc[0].get("threat_score", "0")
                            categories = str(ioc[0].get("categories", ""))
                            update_time = ioc[0].get("update_time", time.time())
                            update_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(update_time))
                            list_data = [group, intranetIp, ip, threat_score, categories, update_time,
                                         log,
                                         standardTimestamp]
                            self.proxy_module.insert_data(ip, threat_score, categories, update_time)
                            self.proxy_module.insert_data_all(group,intranetIp, ip, threat_score, categories, update_time,log,standardTimestamp)
                            print(f'写入情报数据：{list_data}')
                            return list_data
                    elif response.json()["status_code"] == 404:
                        threat_score = None
                        categories = None
                        update_time = None
                        self.proxy_module.insert_data(extranetIp, threat_score, categories, update_time)
                        # print("404不存在情报！")
                        print(f'写入不存在的情报IP：{extranetIp}', str(self.proxy_module.select_data(extranetIp)))
                        # proxy_module.close_connection()
                        break
                    elif response.json()["status_code"] == 409:
                        pass
                        # self.valid_proxy = self.proxy_module.get_valid_proxy()
                    else:
                        pass
                except Exception as err:
                    print(err)
                    pass
        else:
            sql_data = self.proxy_module.select_data(extranetIp)
            print(f'已存在的情报：{str(sql_data)}')
            if sql_data.get('categories') and sql_data.get('categories') != '404':
                ip = sql_data.get('ip','')
                threat_score = sql_data.get('threat_score','')
                categories = sql_data.get('categories','')
                update_time =sql_data.get('update_time','')
                self.proxy_module.insert_data_all(group, intranetIp, ip, threat_score, categories, update_time, log,standardTimestamp)


'''
        else:
            data_list = proxy_module.select_data(self.extranetIp)
            if  data_list.get('threat_score') != '404':
                ip = data_list.get('ip')
                categories = data_list.get('categories')
                threat_score = data_list.get("threat_score")
                update_time = data_list.get("update_time")
                list_data = [self.group, self.intranetIp, ip, threat_score, categories, update_time,
                             self.log,
                             self.standardTimestamp]
                proxy_module.insert_data(self.group, self.intranetIp, ip, threat_score, categories, update_time,self.standardTimestamp,self.log)
                print(f'查找替换的数据：{list_data}')
                #self.proxy_module.close_connection()

            else:
                pass
                '''