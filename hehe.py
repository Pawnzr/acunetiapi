import json
import os
import random
import subprocess
import time
import warnings
from dotenv import load_dotenv
load_dotenv()
import requests
from termcolor import colored
from urllib3.exceptions import InsecureRequestWarning

warnings.simplefilter("ignore", InsecureRequestWarning)
import base64
import hashlib
import os

from flask import Blueprint, request, send_file

routing_acu2 = Blueprint("acu", __name__)


@routing_acu2.route("/acu", methods=["POST"])
def acu():
    data = {}
    url_acunetix = os.getenv("ACUNETIX")
    x_auth = os.getenv("KEY")
    target = request.json["target"]
    scan_speed = request.json["speed"]
    scan_profile_id = request.json["scan_profile"]
    scanned = request.json["scanned"]
    folder_name = "Result/" + hash_message(target) + "/AcuaPi"
    if scanned == "false":
        try:
            if os.path.exists(folder_name):
                try:
                    report_path = f"{folder_name}/Final_report.pdf"
                    if os.path.exists(report_path):
                        with open(report_path, "rb") as file:
                            file_data = file.read()
                            pdf_data = base64.b64encode(file_data).decode("utf-8")
                        data = {
                            "message": "Thong tin scan",
                            "data": json.loads(get_result(folder_name))["data"],
                            "report": pdf_data,
                        }
                    else:
                        data = {
                            "message": "Thong tin scan",
                            "data": json.loads(get_result(folder_name))["data"],
                        }

                except Exception as e:
                    print("error 1:", e)
                    data = {"message": "Domain chua duoc scan", "data": {}}
                return data
            if not os.path.exists(folder_name):
                os.makedirs(folder_name)

            main(url_acunetix, x_auth, target, scan_profile_id, scan_speed, folder_name)
        except Exception as e:
            print("error ocur at ", e)
            return f"Domain chua duoc scan tai vi {e}"
    else:
        try:
            report_path = f"{folder_name}/Final_report.pdf"
            if os.path.exists(report_path):
                with open(report_path, "rb") as file:
                    file_data = file.read()
                    pdf_data = base64.b64encode(file_data).decode("utf-8")
                data = {
                    "message": "Thong tin scan",
                    "data": json.loads(get_result(folder_name))["data"],
                    "report": pdf_data,
                }
            else:
                data = {
                    "message": "Thong tin scan",
                    "data": json.loads(get_result(folder_name))["data"],
                }

        except Exception as e:
            print("error 1:", e)
            data = {"message": "Domain chua duoc scan", "data": {}}
        return data


def get_result(folder_name):
    with open(folder_name + "/scan_status.json", "r") as json_status:
        data_status = json.load(json_status)
    with open(folder_name + "/vuln_status.json", "r") as vuln_file:
        vuln_data = json.load(vuln_file)
    try:
        print(data_status)
        # print(vuln_data)
        vulnerabilities = vuln_data.get("vulnerabilities", [])
        target_id = ""
        # target_id = vulnerabilities["target_id"]
        status = data_status.get("status")
        progress = (
            data_status.get("scanning_app", {})
            .get("wvs", {})
            .get("main", {})
            .get("progress")
        )
        severity_counts = data_status.get("severity_counts")

        exclude_fields = [
            "app",
            "loc_id",
            "status",
            "target_vuln_id",
            "vt_created",
            "vt_id",
            "vt_updated",
            "vuln_id",
        ]

        filtered_vulnerabilities = []
        for vulnerability in vulnerabilities:
            filtered_vulnerability = {
                key: value
                for key, value in vulnerability.items()
                if key not in exclude_fields
            }
            filtered_vulnerabilities.append(filtered_vulnerability)
        target_id = filtered_vulnerabilities[0]["target_id"]
        # target_info = data_status.get("scanning_app", {}).get("wvs", {}).get("hosts", {}).get(f"{target_id}").get("target_info", {})

        combined_data = {
            "status": "Tra ve data thanh cong",
            "data": {
                "status": status,
                "progress": progress,
                "severity_counts": severity_counts,
                "vulnerabilities": filtered_vulnerabilities,
            },
        }
        data = json.dumps(combined_data, indent=4)
        return data
    except Exception as e:
        combined_data = {
            "status": "Tra ve data khong thanh cong",
            "data": {
                "status": status,
                "progress": progress,
                # "target_info":target_info,
                "severity_counts": severity_counts,
                "vulnerabilities": vulnerabilities,
            },
        }
        return combined_data


def hash_message(target):
    sha256 = hashlib.sha256()
    sha256.update(target.encode("utf-8"))
    return str(sha256.hexdigest())


def get_target_id(url_acunetix, address, x_auth):
    headers = {"X-Auth": x_auth, "content-type": "application/json"}
    url = url_acunetix + "targets/add"
    data = {
        "targets": [
            {
                "address": "{}".format(address),
                "description": "AMP scan for {}".format(address),
            }
        ],
        "groups": [],
    }
    try:
        respone = requests.post(
            url, headers=headers, data=json.dumps(data), timeout=30, verify=False
        )
        return str(json.loads(respone.content)["targets"][0]["target_id"])
    except:
        pass


def scan_target(url_acunetix, target_id, x_auth, scan_profile_id, scan_speed):
    headers = {
        "X-Auth": x_auth,
        "Content-Type": "application/json",
        "Cookie": "ui_session={}".format(x_auth),
    }
    url = url_acunetix + "targets/{}/configuration".format(target_id)
    data = {
        "scan_speed": scan_speed,
        "login": {"kind": "none"},
        "ssh_credentials": {"kind": "none"},
        "default_scanning_profile_id": "11111111-1111-1111-1111-111111111111",
        "sensor": "false",
        "case_sensitive": "no",
        "limit_crawler_scope": "true",
        "excluded_paths": [],
        "authentication": {"enabled": "false"},
        "proxy": {"enabled": "false"},
        "technologies": [],
        "custom_headers": [],
        "custom_cookies": [],
        "ad_blocker": "true",
        "debug": "false",
        "skip_login_form": "false",
        "restrict_scans_to_import_files": "false",
        "issue_tracker_id": "",
        "preseed_mode": "",
    }
    try:
        res = requests.patch(
            url, data=json.dumps(data), headers=headers, timeout=30 * 4, verify=False
        )
        data = {
            "profile_id": scan_profile_id,
            "ui_session_id": "c9696e2eb2b52744bbc61e3f47dd20ec",
            "incremental": "false",
            "schedule": {"disable": "false", "time_sensitive": "false"},
            "report_template_id": "11111111-1111-1111-1111-111111111111",
            "target_id": "{}".format(target_id),
        }
        try:
            response = requests.post(
                url_acunetix + "scans",
                headers=headers,
                data=json.dumps(data),
                timeout=30,
                verify=False,
            )
            return str(response.json()["scan_id"])
        except:
            return str(None)
    except:
        return str(None)


def get_session_id(url_acunetix, scan_id, x_auth):
    headers = {
        "X-Auth": x_auth,
        "Cookie": "ui_session={}".format(x_auth),
        "Referer": "https://127.0.0.1:3443/api/v1/",
    }
    url = url_acunetix + "scans/{}".format(scan_id)
    try:
        time.sleep(1)
        response = requests.get(url, headers=headers, timeout=30, verify=False)
        session_id = json.loads(response.content)["current_session"]["scan_session_id"]
        return str(session_id)
    except:
        pass


def show_scan_status(url_acunetix, scan_id, session_id, x_auth, folder_name):
    try:
        headers = {"X-Auth": x_auth, "content-type": "application/json"}
        url = url_acunetix + "scans/{}/results/{}/statistics".format(
            scan_id, session_id
        )
        res = requests.get(url, headers=headers, timeout=30, verify=False)
        with open(folder_name + "/scan_status.json", "w") as f:
            json.dump(json.loads(res.content), f, indent=4)
        progress = json.loads(res.content)["scanning_app"]["wvs"]["main"]["progress"]
        status = json.loads(res.content)["status"]
    except Exception as e:
        progress = 0
        status = 0
    return progress, status


def get_vuln_info(url_acunetix, scan_id, session_id, x_auth, folder_name):
    headers = {"X-Auth": x_auth, "content-type": "application/json"}
    url = url_acunetix + "scans/{}/results/{}/vulnerabilities".format(
        scan_id, session_id
    )
    res = requests.get(url, headers=headers, timeout=30, verify=False)
    with open(folder_name + "/vuln_status.json", "w") as f:
        json.dump(json.loads(res.content), f, indent=4)


def get_reportID(url_acunetix, session_id, x_auth):
    headers = {
        "X-Auth": x_auth,
        "Content-Type": "application/json",
        "Cookie": "ui_session={}".format(x_auth),
    }
    url = url_acunetix + "reports"
    data = {
        "template_id": "11111111-1111-1111-1111-111111111111",
        "source": {"list_type": "scan_result", "id_list": ["{}".format(session_id)]},
    }
    res = requests.post(
        url, headers=headers, data=json.dumps(data), timeout=30, verify=False
    )
    return json.loads(res.content)["report_id"]


def export_report(url_acunetix, report_id, x_auth, folder_name):
    download_link = str(None)
    while download_link == str(None):
        try:
            headers = {
                "X-Auth": x_auth,
                "Content-Type": "application/json",
                "Cookie": "ui_session={}".format(x_auth),
            }
            download_objects = json.loads(
                requests.get(
                    url_acunetix + "reports", headers=headers, timeout=30, verify=False
                ).content
            )["reports"]
            for i in range(len(download_objects)):
                if download_objects[i]["report_id"] == report_id:
                    download_link = download_objects[i]["download"][1]
        except:
            download_link = str(None)
    download_link = download_link.replace("/api/v1/", "")
    url = url_acunetix + download_link
    with open(folder_name + "/Final_report.pdf", "wb") as f:
        headers = {"X-Auth": x_auth, "content-type": "application/json"}
        url = url_acunetix + download_link
        res = requests.get(url, headers=headers, timeout=30, verify=False)
        f.write(res.content)


def main(url_acunetix, x_auth, target, scan_profile_id, scan_speed, folder_name):
    target_id = get_target_id(url_acunetix, target, x_auth)
    print(target_id)
    scan_id = scan_target(url_acunetix, target_id, x_auth, scan_profile_id, scan_speed)
    print(scan_id)
    startTime = time.time()
    session_id = get_session_id(url_acunetix, scan_id, x_auth)
    print(session_id)
    time.sleep(1)
    progress, status = show_scan_status(
        url_acunetix, scan_id, session_id, x_auth, folder_name
    )
    print(progress)
    print(status)
    while True:
        running_time = round(time.time() - startTime)
        if running_time % 500 == 0:
            session_id = get_session_id(url_acunetix, scan_id, x_auth)
        if running_time % 5 == 0:
            progress, status = show_scan_status(
                url_acunetix, scan_id, session_id, x_auth, folder_name
            )
            get_vuln_info(url_acunetix, scan_id, session_id, x_auth, folder_name)
            if status != "processing":
                break

    print(colored("Downloading report...", "blue"), end="\r")
    reportID = get_reportID(url_acunetix, session_id, x_auth)
    time.sleep(2)
    export_report(url_acunetix, reportID, x_auth, folder_name)
    print(colored("Report downloaded successfully!", "green"))
