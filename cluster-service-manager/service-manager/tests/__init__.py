import sys
import unittest
from unittest.mock import MagicMock

sys.modules["interfaces.mongodb_requests"] = unittest.mock.Mock()
mongodb_client = sys.modules["interfaces.mongodb_requests"]
