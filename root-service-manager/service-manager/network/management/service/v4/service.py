import threading
import ipaddress
from typing import List

from interfaces.mongodb import requests
from interfaces.mongodb import service
from network.management.strategy import IPAddressStrategy

class IPv4ServiceStrategy(IPAddressStrategy):
    """
    IPv4 service address allocation strategy (10.30.x.y)
    This also covers instance IPs, as they fall in the same subnetwork
    """
    
    def __init__(self):
        self.lock = threading.Lock()

    def validate_custom_address(self, address: str, job_name: str) -> bool:
        if address is None:
            return False
            
        address_arr = str(address).split(".")
        if len(address_arr) != 4:
            raise Exception("Invalid IPv4 address length")
            
        if address_arr[0] != "10" or address_arr[1] != "30":
            raise Exception("service ip address must be in the form 10.30.x.y")
            
        job = requests.mongo_find_job_by_ip(address)
        if job is not None and job['job_name'] != job_name:
            raise Exception("service ip address already used by another service")
            
        return True

    def get_next_address(self) -> str:
        with self.lock:
            addr = service.mongo_get_service_address_from_cache()
            
            while addr is None:
                addr = service.mongo_get_next_service_ip()
                next_addr = self._increase_address(addr)
                service.mongo_update_next_service_ip(next_addr)
                job = requests.mongo_find_job_by_ip(self.stringify_address(addr))
                if job is not None:
                    addr = None
                    
            return self.stringify_address(addr)

    def clear_address(self, address: str) -> None:
        addr = self.destringify_address(address)

        # Check if address is in the correct range
        assert addr[1] == 30
        assert 0 <= addr[2] < 256
        assert 0 <= addr[3] < 256

        with self.lock:
            next_addr = service.mongo_get_next_service_ip()

            # Ensure that the given address is actually before the next address from the pool
            assert self._compare_addresses(addr, next_addr)

            service.mongo_free_service_address_to_cache(addr)

    def _increase_address(self, addr: List[int]) -> List[int]:
        new2 = addr[2]
        new3 = (addr[3] + 1) % 254
        if new3 == 0:
            new2 = (addr[2] + 1) % 254
            if new2 == 0:
                raise RuntimeError("Exhausted Address Space")
        return [addr[0], addr[1], new2, new3]

    def _compare_addresses(self, addr1: List[int], addr2: List[int]) -> bool:
        addr1_str = ''.join(str(x) for x in addr1[2:4])
        addr2_str = ''.join(str(x) for x in addr2[2:4])
        return int(addr1_str) < int(addr2_str)

    def stringify_address(self, addr: List[int]) -> str:
        return str(ipaddress.ip_address(bytes(addr)))

    def destringify_address(self, addr_str: str) -> List[int]:
        addr = []
        for num in addr_str.split("."):
            addr.append(int(num))
        return addr
