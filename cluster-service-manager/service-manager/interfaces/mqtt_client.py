import re

from interfaces.mongodb_requests import mongo_find_node_by_id_and_update_subnetwork
from network.deployment import *
from network.tablequery import resolution, interests
import paho.mqtt.client as paho_mqtt
import logging

mqtt = None
app = None


def handle_connect(client, userdata, flags, rc):
    global mqtt
    global app
    logging.info("MQTT - Connected to MQTT Broker")
    mqtt.subscribe(topic='nodes/+/net/#', qos=1)


def handle_mqtt_message(client, userdata, message):
    data = dict(
        topic=message.topic,
        payload=message.payload.decode()
    )
    logging.debug('MQTT - Received from worker: ')
    logging.debug(data)

    topic = data['topic']

    re_job_deployment_topic = re.search("^nodes/.*/net/service/deployed", topic)
    re_job_undeployment_topic = re.search("^nodes/.*/net/service/undeployed", topic)
    re_job_tablequery_topic = re.search("^nodes/.*/net/tablequery/request", topic)
    re_job_subnet_topic = re.search("^nodes/.*/net/subnet", topic)
    re_job_interest_remove = re.search("^nodes/.*/net/interest/remove", topic)

    topic_split = topic.split('/')
    client_id = topic_split[1]
    payload = json.loads(data['payload'])

    if re_job_deployment_topic is not None:
        logging.debug('JOB-DEPLOYMENT-UPDATE')
        _deployment_handler(client_id, payload)
    if re_job_undeployment_topic is not None:
        logging.debug('JOB-UNDEPLOYMENT-UPDATE')
        _undeployment_handler(client_id, payload)
    if re_job_tablequery_topic is not None:
        logging.debug('JOB-TABLEQUERY-REQUEST')
        _tablequery_handler(client_id, payload)
    if re_job_subnet_topic is not None:
        logging.debug('JOB-SUBNET-REQUEST')
        _subnet_handler(client_id, payload)
    if re_job_interest_remove is not None:
        logging.debug('JOB-INTEREST-REMOVE')
        _interest_remove_handler(client_id, payload)


def mqtt_init(flask_app):
    global mqtt
    global app
    app = flask_app

    mqtt = paho_mqtt.Client()
    mqtt.on_connect = handle_connect
    mqtt.on_message = handle_mqtt_message
    mqtt.reconnect_delay_set(min_delay=1, max_delay=120)
    mqtt.max_queued_messages_set(1000)
    mqtt.connect(os.environ.get('MQTT_BROKER_URL'), int(os.environ.get('MQTT_BROKER_PORT')), keepalive=5)
    mqtt.loop_start()


def _deployment_handler(client_id, payload):
    appname = payload.get('appname')
    status = payload.get('status')
    nsIp = payload.get('nsip')
    instance_number = payload.get('instance_number')
    host_ip = payload.get('host_ip')
    host_port = payload.get('host_port')
    deployment_status_report(appname, status, nsIp, client_id, instance_number, host_ip, host_port)


def _undeployment_handler(client_id, payload):
    # TODO
    pass


def _interest_remove_handler(client_id, payload):
    appname = payload.get('appname')
    interests.remove_interest(appname, client_id)


def _tablequery_handler(client_id, payload):
    querySname = payload.get('sname')
    serviceName = payload.get('sname')
    sip = payload.get('sip')

    instances = []
    siplist = []
    query_key = ""

    # resolve the query and register interest
    try:
        if sip is not None and sip != "":
            query_key=str(sip)
            serviceName, instances, siplist = resolution.service_resolution_ip(sip)
        elif serviceName is not None and serviceName != "":
            query_key = str(serviceName)
            instances, siplist = resolution.service_resolution(serviceName)
    except Exception as e:
        logging.error(e)
        instances = []
        siplist = []

    interests.add_interest(serviceName, client_id)
    result = {'app_name': serviceName, 'instance_list': resolution.format_instance_response(instances, siplist), 'query_key':query_key}
    mqtt_publish_tablequery_result(client_id, result)


def _subnet_handler(client_id, payload):
    method = payload.get('METHOD')
    if method == 'GET':
        # associate new subnetwork to the node
        addr = root_service_manager_get_subnet()
        mongo_find_node_by_id_and_update_subnetwork(client_id, addr)
        mqtt_publish_subnetwork_result(client_id, {"address": addr})
    elif method == 'DELETE':
        # remove subnetwork from node
        pass


def mqtt_publish_tablequery_result(client_id, result):
    topic = 'nodes/' + client_id + '/net/tablequery/result'
    mqtt.publish(topic, json.dumps(result), qos=1)


def mqtt_publish_subnetwork_result(client_id, result):
    topic = 'nodes/' + client_id + '/net/subnetwork/result'
    mqtt.publish(topic, json.dumps(result), qos=1)


def mqtt_notify_service_change(job_name, type=None):
    topic = 'jobs/' + job_name + '/updates_available'
    mqtt.publish(topic, json.dumps({"type": type}), qos=1)
