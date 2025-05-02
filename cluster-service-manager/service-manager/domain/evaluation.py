from typing import List, Dict, Any

class EvaluationEntry:
    def __init__(self, instance_number: int, priority: float, ip_type: str = None):
        self.instance_number = instance_number
        self.priority = priority
        self.ip_type = ip_type

    def to_dict(self):
        """Convert to a MongoDB-friendly dictionary"""
        return {
            "instance_number": self.instance_number,
            "priority": self.priority,
            "IpType": self.ip_type
        }
        
    def to_json(self):
        """Convert to JSON-serializable dictionary"""
        return self.to_dict()

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            instance_number=data.get("instance_number"),
            priority=data.get("priority"),
            ip_type=data.get("IpType")
        )
        
class EvaluationResult:
    def __init__(self, job_name: str, values: Dict[str, Any], results: List[EvaluationEntry]):
        self.job_name = job_name
        self.values = values
        self.results = results

    def to_dict(self):
        """Convert to a MongoDB-friendly dictionary"""
        return {
            "job_name": self.job_name,
            "values": self.values,
            "results": [result.to_dict() for result in self.results]
        }
        
    def to_json(self):
        """Convert to JSON-serializable dictionary"""
        return self.to_dict()

    @classmethod
    def from_json(cls, data: dict):
        return cls(
            job_name=data.get("job_name"),
            values=data.get("values"),
            results=[EvaluationEntry.from_json(result) for result in data.get("results")]
        )
