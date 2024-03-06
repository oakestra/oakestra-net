import logging
import requests
import os
import json
from interfaces.mongodb_requests import mongo_get_gateway

ROOT_SERVICE_MANAGER_ADDR = (
    "http://"
    + os.environ.get("ROOT_SERVICE_MANAGER_URL", "0.0.0.0")
    + ":"
    + os.environ.get("ROOT_SERVICE_MANAGER_PORT", "5000")
)


def root_service_manager_get_subnet():
    print("Asking the System Manager for a subnet")
    try:
        response = requests.get(ROOT_SERVICE_MANAGER_ADDR + "/api/net/subnet")
        addr = json.loads(response.text).get("subnet_addr")
        addrv6 = json.loads(response.text).get("subnet_addr_v6")
        if len(addr) > 0 and len(addrv6) > 0:
            return [addr, addrv6]
        else:
            raise requests.exceptions.RequestException("No address found")
    except requests.exceptions.RequestException as e:
        print("Calling System Manager /api/net/subnet not successful.")


def system_manager_notify_deployment_status(job, worker_id):
    print("Sending deployment status information to System Manager.")
    data = {
        "job_id": job["system_job_id"],
        "instances": [],
    }
    # prepare json data information
    for instance in job["instance_list"]:
        if instance.get("worker_id") == worker_id:
            elem = {
                "instance_number": instance["instance_number"],
                "namespace_ip": instance["namespace_ip"],
                "namespace_ip_v6": instance["namespace_ip_v6"],
                "host_ip": instance["host_ip"],
                "host_port": instance["host_port"],
            }
            data["instances"].append(elem)
    try:
        logging.info("Sending deployment information to the root")
        logging.debug(job)
        requests.post(
            ROOT_SERVICE_MANAGER_ADDR + "/api/net/service/net_deploy_status", json=data
        )
    except requests.exceptions.RequestException as e:
        print("Calling System Manager /api/result/cluster_deploy not successful.")


def cloud_table_query_ip(ip):
    print("table query to the System Manager...")
    job_ip = ip.replace(".", "_")
    request_addr = (
        ROOT_SERVICE_MANAGER_ADDR + "/api/net/service/ip/" + str(job_ip) + "/instances"
    )
    print(request_addr)
    try:
        return requests.get(request_addr).json()
    except requests.exceptions.RequestException as e:
        print("Calling System Manager /api/job/ip/../instances not successful.")


def cloud_table_query_service_name(name):
    print("table query to the System Manager...")
    job_name = name.replace(".", "_")
    request_addr = (
        ROOT_SERVICE_MANAGER_ADDR + "/api/net/service/" + str(job_name) + "/instances"
    )
    print(request_addr)
    try:
        resp = requests.get(request_addr)
        return resp.json()
    except requests.exceptions.RequestException as e:
        logging.error(e)
        logging.error("Calling System Manager /api/job/../instances not successful.")


def cloud_remove_interest(job_name):
    request_addr = ROOT_SERVICE_MANAGER_ADDR + "/api/net/interest/" + str(job_name)
    try:
        result = requests.delete(request_addr)
        if result.status_code == 404:
            # TODO fallback cluster re-register and re-register the interests
            logging.error(result)
            pass
        if result.status_code != 200:
            # TODO try again later
            logging.error(result)
            pass
    except requests.exceptions.RequestException as e:
        print("Calling System Manager /api/job/../instances not successful.")


def system_manager_notify_gateway_deployment(gateway_info):
    request_addr = ROOT_SERVICE_MANAGER_ADDR + "/api/net/gateway/deploy"
    try:
        result = requests.post(request_addr, json=gateway_info)
        if result.status_code != 200:
            logging.error(result)
        return result.json(), result.status_code
    except requests.exceptions.RequestException:
        print("Calling System Manager /api/net/gateway/deploy not successful.")
        return {"error": "Failed notifying root service-manager"}, 500


def system_manager_notify_gateway_update_service(gateway_id):
    request_addr = ROOT_SERVICE_MANAGER_ADDR + "/api/net/gateway/{}/service".format(
        gateway_id
    )
    try:
        data = mongo_get_gateway(gateway_id)
        del data["_id"]
        requests.put(request_addr, json=data)
    except requests.exceptions.RequestException:
        print(
            "Calling System Manager PUT /api/net/gateway/{}/service not successful.".format(
                gateway_id
            )
        )


def system_manager_notify_gateway_update_namespace(client_id, nsip, nsipv6):
    request_addr = ROOT_SERVICE_MANAGER_ADDR + "/api/net/gateway/{}/namespace".format(
        client_id
    )
    try:
        requests.put(
            request_addr, json={"namespace_ip": nsip, "namespace_ip_v6": nsipv6}
        )
    except requests.exceptions.RequestException:
        print("Calling System Manager PUT /api/net/gateway/namespace not successful.")
