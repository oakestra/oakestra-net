import threading
import ipaddress
from typing import List

from interfaces.mongodb import subnet
from network.management.strategy import IPAddressStrategy


class IPv4SubnetStrategy(IPAddressStrategy):
    """IPv4 subnet address allocation strategy"""
    
    def __init__(self):
        self.lock = threading.Lock()

    def validate_custom_address(self, address: str, job_name: str) -> bool:
        # Not implemented for subnets as they're not user-assignable
        return False

    def get_next_address(self) -> str:
        with self.lock:
            addr = subnet.mongo_get_subnet_address_from_cache()

            if addr is None:
                addr = subnet.mongo_get_next_subnet_ip()
                next_addr = self._increase_address(addr)
                subnet.mongo_update_next_subnet_ip(next_addr)

            return self.stringify_address(addr)

    def clear_address(self, address: str) -> None:
        addr = self.destringify_address(address)

        # Check if address is in the correct rage
        assert 17 < addr[1] < 30
        assert 0 <= addr[2] < 256
        assert addr[3] in [0, 64, 128]

        with self.lock:
            next_addr = subnet.mongo_get_next_subnet_ip()

            # Ensure that the give address is actually before the next address from the pool
            assert self._compare_addresses(addr, next_addr)

            subnet.mongo_free_subnet_address_to_cache(addr)

    def _increase_address(self, addr: List[int]) -> List[int]:
        new1 = addr[1]
        new2 = addr[2]
        new3 = addr[3]
        new3 = (new3 + 64) % 256
        if new3 == 0:
            new2 = (new2 + 1) % 256
        if new2 == 0 and new2 != addr[2]:
            new1 = (new1 + 1) % 30
            if new1 == 0:
                raise RuntimeError("Exhausted Address Space")
        return [addr[0], new1, new2, new3]

    def _compare_addresses(self, addr1: List[int], addr2: List[int]) -> bool:
        addr1_str = ''.join(str(x) for x in addr1[1:4])
        addr2_str = ''.join(str(x) for x in addr2[1:4])
        return int(addr1_str) < int(addr2_str)

    def stringify_address(self, addr: List[int]) -> str:
        return str(ipaddress.ip_address(bytes(addr)))

    def destringify_address(self, addr_str: str) -> List[int]:
        addr = []
        for num in addr_str.split("."):
            addr.append(int(num))
        return addr
