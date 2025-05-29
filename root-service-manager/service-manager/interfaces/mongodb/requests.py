import os
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from datetime import datetime

MONGO_URL = os.environ.get('CLOUD_MONGO_URL')
MONGO_PORT = os.environ.get('CLOUD_MONGO_PORT')

MONGO_ADDR_JOBS = 'mongodb://' + str(MONGO_URL) + ':' + str(MONGO_PORT) + '/jobs'
MONGO_ADDR_NET = 'mongodb://' + str(MONGO_URL) + ':' + str(MONGO_PORT) + '/netcache'
MONGO_ADDR_CLUSTER = 'mongodb://' + str(MONGO_URL) + ':' + str(MONGO_PORT) + '/cluster'

mongo_jobs = None
mongo_clusters = None
mongo_net = None

app = None

CLUSTERS_FRESHNESS_INTERVAL = 45

# IP Operation Constants
# Operation types
OP_GET_FROM_CACHE = "get_from_cache"
OP_FREE_TO_CACHE = "free_to_cache"
OP_GET_NEXT = "get_next"
OP_UPDATE_NEXT = "update_next"

# Address types
ADDR_SERVICE = "service" # IPv6 + ADDR_SERVICE = INSTANCE IPs
ADDR_SUBNET = "subnet"
ADDR_CLOSEST = "closest" # reserved, not implemented
ADDR_RR = "rr"
ADDR_UNDERUTILIZED = "underutilized"
ADDR_FPS = "fps"

# IP versions
IP_V4 = "v4"
IP_V6 = "v6"

def mongo_init(flask_app):
    global app
    global mongo_jobs, mongo_net, mongo_clusters

    app = flask_app

    app.logger.info("Connecting to mongo...")

    # app.config["MONGO_URI"] = MONGO_ADDR
    try:
        mongo_jobs = PyMongo(app, uri=MONGO_ADDR_JOBS)
        mongo_net = PyMongo(app, uri=MONGO_ADDR_NET)
        mongo_clusters = PyMongo(app, uri=MONGO_ADDR_CLUSTER)
    except Exception as e:
        app.logger.fatal(e)
    app.logger.info("MONGODB - init mongo")


# ......... JOB OPERATIONS .........................
####################################################

def mongo_insert_job(obj):
    global mongo_jobs
    app.logger.info("MONGODB - insert job...")
    deployment_descriptor = obj['deployment_descriptor']
    # jobname and details generation
    job_name = deployment_descriptor['app_name'] \
               + "." + deployment_descriptor['app_ns'] \
               + "." + deployment_descriptor['service_name'] \
               + "." + deployment_descriptor['service_ns']
    job_content = {
        'system_job_id': obj.get('system_job_id'),
        'job_name': job_name,
        'service_ip_list': obj.get('service_ip_list'),
        'instance_list': [],
        **deployment_descriptor  # The content of the input deployment descriptor
    }
    if "_id" in job_content:
        del job_content['_id']
    # job insertion
    new_job = mongo_jobs.db.jobs.find_one_and_update(
        {'job_name': job_name},
        {'$set': job_content},
        upsert=True,
        return_document=True
    )
    app.logger.info("MONGODB - job {} inserted".format(str(new_job.get('_id'))))
    return str(new_job.get('_id'))


def mongo_remove_job(system_job_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.delete_one({"system_job_id": system_job_id})


def mongo_get_all_jobs():
    global mongo_jobs
    return mongo_jobs.db.jobs.find()


def mongo_get_job_status(job_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({'_id': ObjectId(job_id)}, {'status': 1})['status'] + '\n'


def mongo_update_job_status(job_id, status):
    global mongo_jobs
    return mongo_jobs.db.jobs.update_one({'_id': ObjectId(job_id)}, {'$set': {'status': status}})


def mongo_update_job_net_status(job_id, instances):
    global mongo_jobs
    for instance in instances:
        mongo_update_job_instance(job_id, instance)

    return mongo_jobs.db.jobs.find_one({'system_job_id': job_id})


def mongo_find_job_by_id(job_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one(ObjectId(job_id))


def mongo_find_job_by_systemid(sys_id):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({"system_job_id": sys_id})


def mongo_find_job_by_name(job_name):
    global mongo_jobs
    return mongo_jobs.db.jobs.find_one({'job_name': job_name})


def mongo_find_job_by_ip(ip):
    global mongo_jobs
    # Search by Service IP
    job = mongo_jobs.db.jobs.find_one({'service_ip_list.Address': ip})
    if job is None:
        # Search by Service IPv6
        job = mongo_jobs.db.jobs.find_one({'service_ip_list.Address_v6': ip})
    if job is None:
        # Search by Instance IP
        job = mongo_jobs.db.jobs.find_one({'instance_list.instance_ip': ip})
    if job is None:
        # Search by Instance IPv6
        job = mongo_jobs.db.jobs.find_one({'instance_list.instance_ip_v6': ip})
    return job


def mongo_update_job_instance(system_job_id, instance):
    global mongo_jobs
    print('Updating job instance')
    mongo_jobs.db.jobs.update_one(
        {
            'system_job_id': system_job_id,
            "instance_list": {'$elemMatch': {'instance_number': instance['instance_number']}}},
        {
            '$set': {
                "instance_list.$.namespace_ip": instance.get('namespace_ip'),
                "instance_list.$.namespace_ip_v6": instance.get('namespace_ip_v6'),
                "instance_list.$.host_ip": instance.get('host_ip'),
                "instance_list.$.host_port": instance.get('host_port'),
            }
        }
    )


def mongo_create_job_instance(system_job_id, instance):
    global mongo_jobs
    print('Updating job instance')
    if not mongo_jobs.db.jobs.find_one(
            {
                "system_job_id": system_job_id,
                "instance_list.instance_number": instance["instance_number"]
            }):
        mongo_jobs.db.jobs.update_one(
            {'system_job_id': system_job_id},
            {
                '$push': {
                    "instance_list": instance
                }
            }
        )
    else:
        mongo_update_job_instance(system_job_id, instance)


def mongo_update_clean_one_instance(system_job_id, instance_number):
    """
    returns the replicas left
    """
    global mongo_jobs
    if instance_number == -1:
        return mongo_jobs.db.jobs.update_one({'system_job_id': system_job_id},
                                             {'$set': {'instance_list': []}})
    else:
        return mongo_jobs.db.jobs.update_one({'system_job_id': system_job_id},
                                             {'$pull': {'instance_list': {'instance_number': instance_number}}})


# ......... CLUSTER OPERATIONS ....................#
####################################################

def mongo_cluster_add(cluster_id, cluster_port, cluster_address, status):
    global mongo_clusters

    mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_id": cluster_id},
        {'$set':
            {
                "cluster_port": cluster_port,
                "cluster_address": cluster_address,
                "status": status,
                "cluster_id": cluster_id
            }
        }, upsert=True)


def mongo_set_cluster_status(cluster_id, cluster_status):
    global mongo_clusters

    job = mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_id": cluster_id},
        {'$set':
             {"status": cluster_status}
         })


def mongo_cluster_remove(cluster_id):
    global mongo_clusters
    mongo_clusters.db.cluster.delete_one({"cluster_id": cluster_id})


def mongo_get_cluster_by_ip(cluster_ip):
    global mongo_clusters
    return mongo_clusters.db.cluster.find_one({"cluster_address": cluster_ip})


# .......... INTERESTS OPERATIONS .........#
###########################################

def mongo_get_cluster_interested_to_job(job_name):
    global mongo_clusters
    return mongo_clusters.db.cluster.find({"interests": job_name})


def mongo_register_cluster_job_interest(cluster_id, job_name):
    global mongo_clusters
    interests = mongo_clusters.db.cluster.find_one({"cluster_id": cluster_id}).get("interests")
    if interests is None:
        interests = []
    if job_name in interests:
        return
    interests.append(job_name)
    mongo_clusters.db.cluster.find_one_and_update(
        {"cluster_id": cluster_id},
        {'$set': {
            "interests": interests
        }}
    )


def mongo_remove_cluster_job_interest(cluster_id, job_name):
    global mongo_clusters
    interests = mongo_clusters.db.cluster.find_one({"cluster_id": cluster_id}).get("interests")
    if interests is not None:
        if job_name in interests:
            interests.remove(job_name)
            mongo_clusters.db.cluster.find_one_and_update(
                {"cluster_id": cluster_id},
                {'$set': {
                    "interests": interests
                }}
    )

# ........... SERVICE MANAGER OPERATIONS  ............
######################################################

def _mongo_ip_operation(operation_type, address_type, address_version, address=None, validators=None):
    """
    Generic function to handle IP address operations with MongoDB
    
    @param operation_type: String indicating the operation type (OP_GET_FROM_CACHE, OP_FREE_TO_CACHE, OP_GET_NEXT, OP_UPDATE_NEXT)
    @param address_type: String indicating the type of address (ADDR_SERVICE, ADDR_RR, ADDR_UNDERUTILIZED, ADDR_SUBNET)
    @param address_version: String indicating IP version (IP_V4, IP_V6)
    @param address: IP address array (required for 'free_to_cache' and 'update_next' operations)
    @param validators: List of validator functions to run on the address
    @return: Depends on operation type
    """
    global mongo_net
    netcache = mongo_net.db.netcache
    
    # Determine field name and document type based on parameters
    ip_field = "ipv4" if address_version == IP_V4 else "ipv6"
    
    doc_type_prefix = address_type
    
    if operation_type == OP_GET_FROM_CACHE:
        doc_type = f"free_{doc_type_prefix}_ip{address_version}"
        entry = netcache.find_one({'type': doc_type})
        
        if entry is not None:
            netcache.delete_one({"_id": entry["_id"]})
            return entry[ip_field]
        else:
            return None
            
    elif operation_type == OP_FREE_TO_CACHE:
        doc_type = f"free_{doc_type_prefix}_ip{address_version}"
        
        # Run validators if provided
        if validators:
            for validator in validators:
                validator(address)
                
        netcache.insert_one({
            'type': doc_type,
            ip_field: address
        })
        
    elif operation_type == OP_GET_NEXT:
        doc_type = f"next_{doc_type_prefix}_ip{address_version}"
        next_addr = netcache.find_one({'type': doc_type})
        
        if next_addr is not None:
            return next_addr[ip_field]
        else:
            # Default initial values
            default_addr_map = {
                IP_V4: {
                    ADDR_SERVICE: [10, 30, 0, 0],
                    ADDR_SUBNET: [10, 18, 0, 0],
                },
                IP_V6: {
                    ADDR_SERVICE: [253, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], # This is the instance address space
                    ADDR_SUBNET: [252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    ADDR_CLOSEST: [253, 255, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    ADDR_RR: [253, 255, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    ADDR_UNDERUTILIZED: [253, 255, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    ADDR_FPS: [253, 255, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                    # Add other address types as needed:
                    # ADDR_NEW_TYPE: [x, y, z, ...],
                }
            }
            default_addr = default_addr_map[address_version][address_type]
            
            netcache.insert_one({
                'type': doc_type,
                ip_field: default_addr
            })
            return default_addr
            
    elif operation_type == OP_UPDATE_NEXT:
        doc_type = f"next_{doc_type_prefix}_ip{address_version}"
        
        # Run validators if provided
        if validators:
            for validator in validators:
                validator(address)
                
        netcache.update_one({'type': doc_type}, {'$set': {ip_field: address}})