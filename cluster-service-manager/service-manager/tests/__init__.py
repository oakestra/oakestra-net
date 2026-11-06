from unittest.mock import MagicMock
import unittest
import sys

sys.modules["interfaces.mongodb_requests"] = unittest.mock.Mock()
mongodb_client = sys.modules["interfaces.mongodb_requests"]
mongodb_client.mongo_get_cluster_id = MagicMock(return_value="1")
