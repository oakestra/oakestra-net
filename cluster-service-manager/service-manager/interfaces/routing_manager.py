import os
import requests
import logging

ROUTING_MANAGER_ADDR = (
  "http://"
  + os.environ.get("ROUTING_MANAGER_URL", "0.0.0.0")
  + ":"
  + os.environ.get("ROUTING_MANAGER_PORT", "8091")
)

INTEREST_ENDPOINT = "/api/v1/interests"


def notify_interest(job_name: str, service_ip: str = "") -> None:
  logging.info(f"Sending interest ({job_name}, {service_ip}) to the Routing Manager...")
  data = {
    "appName": job_name,
    "serviceIp": service_ip
  }
  try:
    requests.post(ROUTING_MANAGER_ADDR + INTEREST_ENDPOINT, json=data)
  except requests.exceptions.RequestException as e:
    logging.error("Calling POST /api/v1/interest to Routing Manager not successful.")


def remove_interest_by_job_name(job_name: str) -> None:
  logging.info(f"Removing interest by job name ({job_name}) from the Routing Manager...")
  try:
    requests.delete(ROUTING_MANAGER_ADDR + INTEREST_ENDPOINT + "/app/" + job_name)
  except requests.exceptions.RequestException as e:
    logging.error("Calling DELETE /api/v1/interest/app/" + job_name + " to Routing Manager not successful.")


def remove_interest_by_service_ip(service_ip: str) -> None:
  logging.info(f"Removing interest by service IP ({service_ip}) from the Routing Manager...")
  try:
    requests.delete(ROUTING_MANAGER_ADDR + INTEREST_ENDPOINT + "/service/" + service_ip)
  except requests.exceptions.RequestException as e:
    logging.error("Calling DELETE /api/v1/interest/service/" + service_ip + " to Routing Manager not successful.")

