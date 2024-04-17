from interfaces.mongodb_requests import (
    mongo_add_gateway,
    mongo_add_gateway_job,
    mongo_update_gateway_namespace,
    mongo_update_gateway_service,
    mongo_get_all_gateways,
)
from network.subnetwork_management import new_instance_ip, new_instance_ip_v6


def gateway_deploy(gateway_info):
    """
    Get instance IPs for the gateway and register gateway
    Returns new gateway job
    """
    ipv4 = None
    ipv6 = None
    if gateway_info.get("gateway_ipv4") is not None:
        ipv4 = new_instance_ip()
    if gateway_info.get("gateway_ipv6") is not None:
        ipv6 = new_instance_ip_v6()

    gateway_info["instance_ip"] = ipv4
    gateway_info["instance_ip_v6"] = ipv6

    mongo_add_gateway(gateway_info)

    # create job to make tablequerys work
    gw_job = _prepare_gateway_job_dict(gateway_info)
    mongo_add_gateway_job(gw_job)
    gw_job.pop("_id", None)

    return gw_job, 200


def update_gateway_namespace(gateway_id, nsip, nsipv6):
    mongo_update_gateway_namespace(gateway_id, nsip, nsipv6)
    return "ok", 200


def update_gateway_service(gateway_id, data):
    mongo_update_gateway_service(gateway_id, data)
    return "ok", 200


def get_gateways():
    return mongo_get_all_gateways(), 200


def _prepare_gateway_job_dict(gateway_info):
    """
    Create a job entry for the gateway in order to make
    table queries by proxys resolve to the gateway
    adds to the gateway description:
    instance_list: [{
                    instance_number: int
                    instance_ip: string
                    instance_ip_v6: string
                    namespace_ip: string
                    namespace_ip_v6: string
                    host_ip: string
                    host_port: int
                    }]
    service_ip_list: [{
                        IpType: string
                        Address: string
                        Address_v6: string
                    }]
    """
    data = {}
    data["gateway_id"] = gateway_info["gateway_id"]
    data["job_name"] = gateway_info["host"] + ".oakestra.gateway.0"
    data["system_job_id"] = gateway_info["gateway_id"]
    data["instance_list"] = [
        {
            "instance_number": 0,
            "cluster_id": gateway_info["cluster_id"],
            "instance_ip": gateway_info["instance_ip"],
            "instance_ip_v6": gateway_info["instance_ip_v6"],
            "namespace_ip": gateway_info.get("namespace_ip"),
            "namespace_ip_v6": gateway_info.get("namespace_ip_v6"),
            # TODO: make IPv6?
            "host_ip": gateway_info["gateway_ipv4"],
            "host_ip_v6": gateway_info["gateway_ipv6"],
            "host_port": gateway_info["host_port"],
        }
    ]
    # gateways do not have service IPs for now
    data["service_ip_list"] = []
    data["interested_nodes"] = []
    return data
