import logging
import os
import requests

from network.utils import sanitize
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

NOTIFY_INTEREST_ENDPOINT = "/api/net/job/update"

logger = logging.getLogger("root_service_manager")


ROOT_CERT_FILE = os.environ.get("ROOT_CERT_FILE")
ROOT_KEY_FILE = os.environ.get("ROOT_KEY_FILE")
ROOT_CA_FILE = os.environ.get("ROOT_CA_FILE")

# Manual port override in case cluster is behind gateway
CLUSTER_GATEWAY_PORT = os.environ.get("CLUSTER_GATEWAY_PORT")


def _mtls_enabled() -> bool:
    return all(
        path and os.path.isfile(path)
        for path in (ROOT_CERT_FILE, ROOT_KEY_FILE, ROOT_CA_FILE)
    )


def notify_undeployment(cluster_addr, cluster_port, job_name, instancenum):
    logging.debug("Notifying undeployment of " + job_name + " to a cluster")
    return _notify_interest_update(
        cluster_addr, cluster_port, job_name, instancenum, "UNDEPLOYMENT"
    )


def notify_deployment(cluster_addr, cluster_port, job_name, instancenum):
    return _notify_interest_update(
        cluster_addr, cluster_port, job_name, instancenum, "DEPLOYMENT"
    )


def _notify_interest_update(cluster_addr, cluster_port, job_name, instancenum, type):
    mtls = _mtls_enabled()
    scheme = "https" if mtls else "http"
    port = CLUSTER_GATEWAY_PORT if (mtls and CLUSTER_GATEWAY_PORT) else cluster_port
    return request_with_retry(
        url=scheme
        + "://"
        + sanitize(cluster_addr, request=True)
        + ":"
        + str(port)
        + NOTIFY_INTEREST_ENDPOINT,
        json={"job_name": job_name, "instance_number": instancenum, "type": type},
    )


def request_with_retry(url, json):
    s = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))

    if _mtls_enabled():
        s.cert = (ROOT_CERT_FILE, ROOT_KEY_FILE)
        s.verify = ROOT_CA_FILE

    session = s.post(url=url, json=json, timeout=2)
    return session.status_code
