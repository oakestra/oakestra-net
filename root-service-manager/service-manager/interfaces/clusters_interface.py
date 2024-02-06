import logging
import requests
import socket
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

NOTIFY_INTEREST_ENDPOINT = "/api/net/job/update"

logging.basicConfig(level=logging.DEBUG)


def notify_undeployment(cluster_addr, cluster_port, job_name, instancenum):
    logging.debug("Notifying undeployment of " + job_name + " to a cluster")
    return _notify_interest_update(
        cluster_addr, cluster_port, job_name, instancenum, "UNDEPLOYMENT"
    )


def notify_deployment(cluster_addr, cluster_port, job_name, instancenum):
    logging.debug("Notifying deployment of " + job_name + " to a cluster")
    return _notify_interest_update(
        cluster_addr, cluster_port, job_name, instancenum, "DEPLOYMENT"
    )


def _notify_interest_update(cluster_addr, cluster_port, job_name, instancenum, type):
    return request_with_retry(
        url="http://"
        + sanitize(cluster_addr, request=True)
        + ":"
        + str(cluster_port)
        + NOTIFY_INTEREST_ENDPOINT,
        json={"job_name": job_name, "instance_number": instancenum, "type": type},
    )


def request_with_retry(url, json):
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retries))

    session = s.post(url=url, json=json, timeout=2)
    return session.status_code


def sanitize(address, request=False):
    """
    Sanitizes address to conform with request format.
    Adds brackets if a valid IPv6 address is given and
    the sanitization is for a HTTP request.
    Removes 4to6 mapped address part for valid IPv4 format,
    if a 4to6 mapped IPv4 address is given.
    """
    if is_4to6_mapped(address):
        return extract_v4_address_from_v6_mapped(address)
    if request:
        return add_brackets_if_ipv6(address)
    return address


def is_ipv6(address):
    """Checks if the given address is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False


def add_brackets_if_ipv6(address):
    """Adds brackets to the address if it's IPv6 and doesn't have them."""
    if is_ipv6(address) and not address.startswith("["):
        return f"[{address}]"
    else:
        return address


def is_4to6_mapped(address):
    """Checks if the given address is 4-to-6 mapped."""
    return is_ipv6(address) and address.startswith("::")


def extract_v4_address_from_v6_mapped(address):
    """Returns IPv4 address, given address is a 4-to-6 mapped IP address"""
    return address.split(":")[3]
