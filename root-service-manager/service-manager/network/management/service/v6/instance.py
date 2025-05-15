import threading
import ipaddress
from typing import List

from interfaces.mongodb import requests
from interfaces.mongodb import service
from network.management.strategy import IPAddressStrategy


class IPv6InstanceStrategy(IPAddressStrategy):
    """IPv6 instance address allocation strategy (fdff::/21)"""
    
    def __init__(self):
        self.lock = threading.Lock()

    def validate_custom_address(self, address: str, job_name: str) -> bool:
        if address is None:
            return False
            
        # because shorthand IPv6 addresses can be given in SLA, make sure to use expanded IPv6 notation for consistency with MongoDB requests
        address_arr = ipaddress.ip_address(address).exploded.split(":")
        if len(address_arr) != 8:
            raise Exception("Invalid IPv6 address length")
            
        # Check for instance IP range (fdff::/21)
        if address_arr[0] != "fdff" or (address_arr[1][0:2] != "00" and address_arr[1][0:2] != "08"):
            raise Exception("Instance IP address must be in the subnet fdff::/21 or fdff:0800::/21")
            
        job = requests.mongo_find_job_by_ip(address)
        if job is not None and job['job_name'] != job_name:
            raise Exception("IPv6 address already used by another service")
            
        return True

    def get_next_address(self) -> str:
        with self.lock:
            addr = service.mongo_get_service_address_from_cache_v6()
            
            while addr is None:
                addr = service.mongo_get_next_service_ip_v6()
                next_addr = self._increase_address(addr)
                service.mongo_update_next_service_ip_v6(next_addr)
                job = requests.mongo_find_job_by_ip(self.stringify_address(addr))
                if job is not None:
                    addr = None
                    
            return self.stringify_address(addr)

    def clear_address(self, address: str) -> None:
        addr = self.destringify_address(address)

        # Check if address is in the correct range
        assert addr[0] == 253
        assert addr[1] == 255
        assert addr[2] == 0 or addr[2] == 8
        
        with self.lock:
            next_addr = service.mongo_get_next_service_ip_v6()

            # Ensure that the given address is actually before the next address from the pool
            assert self._compare_addresses(addr, next_addr)

            service.mongo_free_service_address_to_cache_v6(addr)

    def _increase_address(self, addr: List[int]) -> List[int]:
        # convert subnet portion of addr to int and increase by one
        addr_int = int.from_bytes(addr[6:16], byteorder='big')
        addr_int += 1

        # reconvert new address part to bytearray and concatenate it with the network part of addr
        # will raise RuntimeError if address space is exhausted
        try:
            new_addr = addr_int.to_bytes(10, byteorder='big')
            new_addr = addr[0:6] + list(new_addr)
            return new_addr
        except OverflowError:
            # if first fdff:0000::/21 instance ip block is full, use next one: fdff:0800::/21
            # for every other balancing strategy, this also decides correctly and throws the below RuntimeError
            if addr[2] == 0:
                return [253, 255, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
            # if that one is also full, no more addresses
            else:
                raise RuntimeError("Exhausted Instance IP address space")

    def _compare_addresses(self, addr1: List[int], addr2: List[int]) -> bool:
        addr1_str = ''.join(str(x) for x in addr1[6:16])
        addr2_str = ''.join(str(x) for x in addr2[6:16])
        return int(addr1_str) < int(addr2_str)

    def stringify_address(self, addr: List[int]) -> str:
        return str(ipaddress.ip_address(bytes(addr)))

    def destringify_address(self, addr_str: str) -> List[int]:
        addr = []
        # get long notation of IPv6 addr str
        for num in ipaddress.ip_address(addr_str).exploded.split(":"):
            addr.append(int(num[0:2], 16))
            addr.append(int(num[2:4], 16))
        return addr
