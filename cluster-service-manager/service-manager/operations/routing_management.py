from domain.evaluation import EvaluationResult
from interfaces.mongodb_requests import mongo_update_job_routing
from operations.instances_management import _update_cache_and_workers

def update_job_routing(req_json: dict):
    """
       Update the routing priority table of a job
    """
    evaluation_result = EvaluationResult.from_json(req_json)
    mongo_update_job_routing(evaluation_result)
    return "Routing updated", 200


def update_job_routing_alert(req_json: dict):
    """
       Alert regarding a routing change
    """
    evaluation_result = EvaluationResult.from_json(req_json)
    mongo_update_job_routing(evaluation_result)
    # send out, that an update is available, forcing the network managers to update their routing tables
    _update_cache_and_workers(evaluation_result.job_name, -1, "ROUTING_CHANGE")
    return "Routing updated", 200