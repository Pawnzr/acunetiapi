import requests
import urllib3

urllib3.disable_warnings()
import json
import logging
import os
from urllib.parse import urlparse

db_logger = logging.getLogger("db")


class AcunetixWrapper:
    """
    provide simple api for working with remote acunetix
    """

    base_url = os.getenv("ACUNETIX_URL")
    authentication_api = os.getenv("ACUNETIX_API")
    # headers = {'X-Auth':authentication_api, 'Content-Type':'application/json', 'Accept':"application/json"}
    full_scan_id = "11111111-1111-1111-1111-111111111111"

    @property
    def headers(self):
        return {
            "X-Auth": self.authentication_api,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def is_dead(self):
        try:
            requests.get(self.base_url, headers=self.headers, verify=False, timeout=180)
            return False
        except Exception as e:
            db_logger.exception(e)
            return True

    def get_target(self, target_id):
        url = f"{self.base_url}/targets/{target_id}"
        response = requests.get(url, headers=self.headers, verify=False, timeout=180)
        if response.status_code == 200:
            return 0
        elif response.status_code == 404:
            raise ValueError("Mục tiêu không tồn tại trên server Acunetix")
        else:
            raise ConnectionError("Gặp lỗi khác khi kết nối với server Acunetix")

    def add_target(self, target_address):
        body = {
            "address": target_address,
            "description": "",
            "type": "default",
            "criticality": 10,
        }

        response = requests.post(
            f"{self.base_url}/targets",
            json=body,
            headers=self.headers,
            verify=False,
            timeout=180,
        )
        print(response.status_code)
        if response.status_code == 201:
            target_id = response.json().get("target_id")
            return target_id
        else:
            raise ConnectionError("Please check the API and Base URL")

    def configure_target(self, target_id):
        url = f"{self.base_url}/targets/{target_id}/configuration"
        ssr = {
            1: "sequential",
            2: "slow",
            3: "moderate",
            4: "fast",
        }
        scan_speed = ssr.get(self.options.get("scanSpeedOption"), 3)
        proxy = {}
        body = {"debug": True}
        body.update({"scan_speed": scan_speed})
        if self.options.get("proxyCheck"):
            body.update({"proxy": proxy})
            proxy.update({"enabled": True})
            proxy.update(
                {
                    "protocol": self.options.get("proxyScheme").lower(),
                    "address": self.options.get("proxyAdress"),
                    "port": self.options.get("proxyPort"),
                }
            )
            if self.options.get("proxyAuthenticationCheck"):
                proxy.update(
                    {
                        "username": self.options.get("proxyUsername"),
                        "password": self.options.get("proxyUserPassword"),
                    }
                )
        if self.options.get("headerOptionCheck"):
            body.update(
                {
                    "custom_headers": self.options.get("headerOptionValue"),
                }
            )

        response = requests.patch(
            url, json=body, headers=self.headers, verify=False, timeout=180
        )

        if response.status_code == 204:
            print("Proxy Config Complete")
        elif response.status_code == 404:
            raise ValueError("Target ID incorrect or not exist")
        else:
            raise ConnectionError("Server không chấp nhận gửi lên")

    def get_vulnerabilities(self, target_id):
        return requests.get(
            f"{self.base_url}/vulnerabilities?q=target_id:{target_id}",
            headers=self.headers,
            verify=False,
            timeout=180,
        )

    def get_scan_result(self, scan_id, status=False, end_date=False):
        url = f"{self.base_url}/scans/{scan_id}/results"
        response = requests.get(
            url=url, headers=self.headers, verify=False, timeout=180
        )
        if status == True:
            if response.status_code == 200:
                try:
                    return response.json()["results"][0]["status"]
                except Exception as e:
                    db_logger.exception(e)
                    return None
            else:
                return None
        if end_date == True:
            if response.status_code == 200:
                try:
                    return [
                        response.json()["results"][0]["status"],
                        response.json()["results"][0]["end_date"],
                    ]
                except Exception as e:
                    db_logger.exception(e)
                    return None
            else:
                return None

        if response.status_code == 200:
            result_id = response.json()["results"][0]["result_id"]
            return result_id
        else:
            raise ConnectionError("Can not get Scan Results")

    def schedule_scan(self, target_id):

        scan_body = {
            "profile_id": self.full_scan_id,
            "incremental": False,
            "schedule": {"disable": False, "time_sensitive": False},
            # "schedule": {
            #     "disable": False,
            #     "time_sensitive": True,
            #     "recurrence": "DTSTART:20230815T010000Z\nFREQ=DAILY"
            # },
            "user_authorized_to_scan": "yes",
            "target_id": target_id,
        }
        scan_url = f"{self.base_url}/scans"
        response = requests.post(
            scan_url, json=scan_body, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 201:
            scan_id = response.headers["Location"].replace("/api/v1/scans/", "")
            return scan_id
        else:
            raise ConnectionError("Schedule Scan Failed")

    def stop_scan(self, scan_id):
        scan_url = f"{self.base_url}/scans/{scan_id}/abort"
        response = requests.post(
            scan_url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 204:
            return 0
        else:
            raise RuntimeError()

    def pause_scan(self, scan_id):
        scan_url = f"{self.base_url}/scans/{scan_id}/pause"
        response = requests.post(
            scan_url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 204:
            return 0
        else:
            raise RuntimeError()

    def continue_scan(self, scan_id):

        status = self.get_scan_result(scan_id=scan_id, status=True)
        scan_url = f"{self.base_url}/scans/{scan_id}/resume"
        response = requests.post(
            scan_url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 204:
            return 0
        else:
            raise RuntimeError("Gặp lỗi khi request acunetix server")

    def trigger_scan(self, scan_id):
        status = self.get_scan_result(scan_id=scan_id, status=True)
        scan_url = f"{self.base_url}/scans/{scan_id}/trigger"
        response = requests.post(
            scan_url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 204:
            return 0
        elif response.status_code == 209:
            raise RuntimeError("Không thể trigger scan")
        else:
            raise RuntimeError("")

    def get_scan_status(self, scan_id):
        url = f"{self.base_url}/scans/{scan_id}"
        response = requests.get(url, headers=self.headers, verify=False, timeout=180)
        if response.status_code == 200:
            return response.json()
        else:
            raise ConnectionError("Can not get Scan Status")

    def get_scan_statistical_result(self, scan_id, result_id, fail=False):
        url = f"{self.base_url}/scans/{scan_id}/results/{result_id}/statistics"
        if fail == True:
            url = f"{self.base_url}/scans/{scan_id}"
        response = requests.get(url, headers=self.headers, verify=False, timeout=180)
        if response.status_code == 200:
            return response.json()
        else:
            raise ConnectionError("Can not get Scan Result Statistic")

    def get_vul_by_result(self, scan_id, result_id):
        url = f"{self.base_url}/scans/{scan_id}/results/{result_id}/vulnerabilities"
        response = requests.get(
            url=url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 200:
            return response.json()
        else:
            raise ConnectionError("Error when Get Vul list")

    def check_status(self, scan_id):
        self.scan_status(scan_id)
        result_id = self.get_scan_result(scan_id)
        vuls = self.get_vul_by_result(scan_id, result_id)
        return vuls

    def get_vul_detail(self, scan_id, result_id, vul_id) -> dict:
        url = f"{self.base_url}/scans/{scan_id}/results/{result_id}/vulnerabilities/{vul_id}"
        u2 = f"{self.base_url}/scans/{scan_id}/results/{result_id}/vulnerabilities/{vul_id}/http_response"
        response = requests.get(
            url=url, headers=self.headers, verify=False, timeout=180
        )
        r2 = requests.get(url=u2, headers=self.headers, verify=False, timeout=180)
        if response.status_code == 200:
            r = response.json()
            r["http_response"] = r2.content.decode()
            return r
        else:
            raise ConnectionError("Can not get Vul Detail")

    def all_vul_detail(self, vuls):
        r = []
        for i in vuls["vulnerabilities"]:
            vul_id = i["vuln_id"]
            self.get_vul_detail(vul_id=vul_id)
        return r

    def get_vul_by_target_id(self, target_id):
        url = f"{self.base_url}/vulnerabilities?q=target_id:{target_id}"
        response = requests.get(
            url=url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 200:
            data = response.json()
            pagination = data["pagination"]
            count = pagination["count"]
            if count <= 100:
                return data
            else:
                cursors = pagination["cursors"]
                while len(cursors) > 1:
                    next_page = cursors[1]
                    next_page_data = self.cursor_get(target_id, cursor=next_page)
                    pagination = next_page_data["pagination"]
                    cursors = pagination["cursors"]
                    data["vulnerabilities"] += next_page_data["vulnerabilities"]
                # print(len(data["vulnerabilities"]))
                return data
        else:
            raise ConnectionError("Can not get Vul")

    def cursor_get(self, target_id, cursor=None):
        # print(cursor)
        """
        acunetix nhận param q, trong đó set target_id để lọc query theo target_id
        param c là cursor cho request
        acunetix trả về 1 array có chứa cursor liền kề, theo thứ tự: cursor hiện tại, cursor tiếp, và kế
        khi cursors trả về chứa 1 cursor thì đó là trang cuối
        """
        response = requests.get(
            url=self.base_url + f"/vulnerabilities?q=target_id:{target_id}&c={cursor}",
            headers=self.headers,
            verify=False,
            timeout=180,
        )
        # print(response.url)
        if response.status_code == 200:
            return response.json()
        else:
            raise ConnectionError("Can not get Vul")

    def get_vul_detail_by_target_id(self, vuln_Id):
        url = f"{self.base_url}/vulnerabilities/{vuln_Id}"
        u2 = f"{url}/http_response"
        r2 = requests.get(url=u2, headers=self.headers, verify=False, timeout=180)
        response = requests.get(
            url=url, headers=self.headers, verify=False, timeout=180
        )
        if response.status_code == 200:
            r = response.json()
            r["http_response"] = r2.content.decode()
            return r
        else:
            raise ConnectionError("Can not get Vul")

    def get_download(self, scan_id, download_id, path):
        url = f"{self.base_url}/exports"
        xml_download = requests.get(
            f"{url}/{download_id}", headers=self.headers, verify=False, timeout=180
        )
        if xml_download.status_code == 200:
            status = xml_download.json()["status"]
            if status == "completed":
                link = xml_download.json()["download"][0]
                location = urlparse(url)
                r = location._replace(path=link).geturl()
                r = requests.get(
                    r,
                    allow_redirects=True,
                    headers=self.headers,
                    verify=False,
                    timeout=180,
                )
                try:
                    open(f"{path}/{scan_id}.xml", "wb").write(r.content)
                except Exception as e:
                    db_logger.exception(e)
                    raise IOError(
                        "File can not created, please check the storage permission"
                    )
                return "completed"
            else:
                print(xml_download.content)
                return None
        else:
            print(xml_download)
            return None

    def create_download(self, scan_id):
        payload = json.dumps(
            {
                "export_id": "21111111-1111-1111-1111-111111111111",
                "source": {"list_type": "scans", "id_list": [scan_id]},
            }
        )
        url = f"{self.base_url}/exports"
        response = requests.request(
            "POST", url, headers=self.headers, data=payload, verify=False, timeout=180
        )
        if response.status_code == 201:
            download_id = response.json()["report_id"]
            return download_id
        else:
            raise ConnectionError("Can not create xml report")


api = AcunetixWrapper()
api.base_url = "https://192.168.245.129:3443/api/v1"
api.authentication_api = (
    "1986ad8c0a5b3df4d7028d5f3c06e936c2d8d0b459a674c9a91d66c609a8284d2"
)
# print(api.base_url)
# target_id=api.add_target("https://happyorder.vn")
# scan_id = api.schedule_scan(target_id)
scan_id = "fceadb77-b7a3-4bc8-9ccf-26ce0628f5d3"
target_id="cafc8394-8ee8-4da3-8e35-7ad42f7d6ed5"
vulns = api.get_vul_by_target_id(target_id)

print(json.dumps(vulns,  indent=4, sort_keys=True))
