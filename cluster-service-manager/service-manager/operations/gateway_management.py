from interfaces.mongodb_requests import (
    mongo_add_gateway,
    mongo_add_gateway_job,
    mongo_get_service_ips_by_jobname,
    mongo_add_service_to_gateway,
)
from interfaces.root_service_manager_requests import (
    system_manager_notify_gateway_deployment,
    system_manager_notify_gateway_update_service,
)
from interfaces.mqtt_client import (
    mqtt_publish_gateway_deploy,
    mqtt_publish_gateway_firewall_expose,
)


def deploy_gateway(gateway_info):
    """
    Register new gateway and notify root service manager
    """

    # notifies root service-manager, which directly hands out instance IPs for gateway service
    # returns gateway_job to add to jobs table for tablequery functionality
    gw_job, status = system_manager_notify_gateway_deployment(gateway_info=gateway_info)
    if status != 200:
        return "", status

    gateway_info["instance_ip"] = gw_job["instance_ip"]
    gateway_info["instance_ip_v6"] = gw_job["instance_ip_v6"]
    mongo_add_gateway(gateway_info)

    # add job to service job table
    mongo_add_gateway_job(gw_job)
    del gw_job["_id"]

    mqtt_msg = _prepare_mqtt_deploy_message(gw_job)
    mqtt_publish_gateway_deploy(gw_job["gateway_id"], mqtt_msg)
    return gw_job, 200


def update_gateway_service_exposure(gateway_id, service_info):
    """
    Update gateway db, notify root service manager and notify gateway node over MQTT
    """

    mongo_add_service_to_gateway(gateway_id, service_info)

    mqtt_msg = _prepare_mqtt_expose_message(gateway_id, service_info)

    service_ips = mongo_get_service_ips_by_jobname(service_info["job_name"])[
        "service_ip_list"
    ]
    # TODO: make respect IP Type here
    # when we start supporting more service IP types
    for service_ip in service_ips:
        # currently only holds RR IPs
        if service_ip.get("Address") is not None:
            mqtt_msg["service_ip"] = service_ip["Address"]
            mqtt_publish_gateway_firewall_expose(gateway_id, mqtt_msg)
        if service_ip.get("Address_v6") is not None:
            mqtt_msg["service_ip"] = service_ip["Address_v6"]
            mqtt_publish_gateway_firewall_expose(gateway_id, mqtt_msg)

    system_manager_notify_gateway_update_service(gateway_id)
    return "ok", 200


def _prepare_mqtt_deploy_message(gw_job):
    msg = {}
    instance_list = gw_job["instance_list"][0]
    msg["gateway_id"] = gw_job["gateway_id"]
    msg["job_name"] = gw_job["job_name"]
    msg["instance_ip"] = instance_list["instance_ip"]
    msg["instance_ip_v6"] = instance_list["instance_ip_v6"]
    msg["gateway_ipv4"] = instance_list["host_ip"]
    msg["gateway_ipv6"] = instance_list["host_ip_v6"]
    return msg


def _prepare_mqtt_expose_message(gateway_id, service_info):
    msg = {}
    msg["gateway_id"] = gateway_id
    msg["service_id"] = service_info["microserviceID"]
    msg["exposed_port"] = service_info["exposed_port"]
    msg["internal_port"] = service_info["internal_port"]
    return msg
