from interfaces import mongodb_requests
from interfaces.root_service_manager_requests import *
import threading


def deployment_status_report(
    appname, status, NsIp, NsIPv6, node_id, instance_number, host_ip, host_port
):
    # Update mongo job
    job = mongodb_requests.mongo_update_job_deployed(
        appname, status, NsIp, NsIPv6, node_id, instance_number, host_ip, host_port
    )
    if job is None:
        raise FileNotFoundError
    # Notify System manager
    threading.Thread(target=system_manager_notify_deployment_status, args=(job, node_id)).start()