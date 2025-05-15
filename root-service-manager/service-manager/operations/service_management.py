from network.management.manager import ip_manager, STRATEGY_IPV4_SERVICE, STRATEGY_IPV6_RR, STRATEGY_IPV6_UNDERUTILIZED, STRATEGY_IPV6_CLOSEST
from interfaces.mongodb.requests import *
from utils.sla_validation import check_valid_sla

@check_valid_sla
def deploy_request(deployment_descriptor=None, system_job_id=None):
    if system_job_id is None:
        return "Invalid system_job_id", 400

    job_name = deployment_descriptor.get('app_name') + "." + deployment_descriptor.get('app_ns') + "." + deployment_descriptor.get('service_name') + "." + deployment_descriptor.get('service_ns')

    s_ip = [{
        "IpType": 'RR',
        "Address": ip_manager.new_address(STRATEGY_IPV4_SERVICE, deployment_descriptor.get('RR_ip'), job_name),
        "Address_v6": ip_manager.new_address(STRATEGY_IPV6_RR, deployment_descriptor.get('RR_ip_v6'), job_name)
    },
    {
        "IpType": 'underutilized',
        "Address": ip_manager.new_address(STRATEGY_IPV4_SERVICE, deployment_descriptor.get('underutilized_ip'), job_name),
        "Address_v6": ip_manager.new_address(STRATEGY_IPV6_UNDERUTILIZED, deployment_descriptor.get('underutilized_ip_v6'), job_name)
    },
    {
        "IpType": 'closest',
        "Address": ip_manager.new_address(STRATEGY_IPV4_SERVICE, deployment_descriptor.get('closest_ip'), job_name),
        "Address_v6": ip_manager.new_address(STRATEGY_IPV6_CLOSEST, deployment_descriptor.get('closest_ip_v6'), job_name)
    }]
    job_id = mongo_insert_job(
        {
            'system_job_id': system_job_id,
            'deployment_descriptor': deployment_descriptor,
            'service_ip_list': s_ip
        })
    return "Instance info added", 200


def remove_service(system_job_id=None):
    if system_job_id is None:
        return "Invalid input parameters", 400

    job = mongo_find_job_by_systemid(system_job_id)

    if job is None:
        return "Invalid input parameters", 400

    instances = job.get("instance_list")

    if instances is not None:
        if len(instances) > 0:
            return "There are services still deployed", 400

    mongo_remove_job(system_job_id)
    return "Job removed successfully", 200
