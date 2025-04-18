from interfaces import mongodb_requests
from interfaces import root_service_manager_requests
from interfaces import routing_manager
from interfaces import mqtt_client
from interfaces.mongodb_requests import mongo_remove_job
import logging

def remove_interest(job_name,clientid):
    """
    remove the interest for the service if no other worker node is interested
    """
    mongodb_requests.mongo_remove_interest(job_name, clientid)
    if not is_job_relevant_for_the_cluster(job_name):
        root_service_manager_requests.cloud_remove_interest(job_name)
        routing_manager.remove_interest_by_job_name(job_name)
        mongo_remove_job(job_name)


def add_interest(job_name, clientid, service_ip: str = None):
    if clientid not in mongodb_requests.mongo_get_interest_workers(job_name):
        mongodb_requests.mongo_add_interest(job_name, clientid)
        routing_manager.notify_interest(job_name, service_ip)


def is_job_relevant_for_the_cluster(job_name):
    interested = mongodb_requests.mongo_get_interest_workers(job_name)
    if interested is None:
        return False
    return len(interested) > 0
