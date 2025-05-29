import ipaddress
from typing import List

from interfaces.mongodb import requests
from interfaces.mongodb import fps
from .instance import IPv6InstanceStrategy


class IPv6FPSStrategy(IPv6InstanceStrategy):
    """IPv6 FPS address allocation strategy"""
    
    def validate_custom_address(self, address: str, job_name: str) -> bool:
        if address is None:
            return False
            
        # because shorthand IPv6 addresses can be given in SLA, make sure to use expanded IPv6 notation for consistency with MongoDB requests
        address_arr = ipaddress.ip_address(address).exploded.split(":")
        if len(address_arr) != 8:
            raise Exception("Invalid IPv6 address length")
            
        # Check for FPS IP range (fdff:4000::/21)
        if address_arr[0] != "fdff" or address_arr[1][0:2] != "40":
            raise Exception("FPS IP address must be in the subnet fdff:4000::/21")
            
        job = requests.mongo_find_job_by_ip(address)
        if job is not None and job['job_name'] != job_name:
            raise Exception("FPS IPv6 address already used by another service")
            
        return True

    def get_next_address(self) -> str:
        with self.lock:
            addr = fps.mongo_get_fps_address_from_cache_v6()
            while addr is None:
                addr = fps.mongo_get_next_fps_ip_v6()
                next_addr = self._increase_address(addr)
                fps.mongo_update_next_fps_ip_v6(next_addr)
                job = requests.mongo_find_job_by_ip(self.stringify_address(addr))
                if job is not None:
                    addr = None

            return self.stringify_address(addr)

    def clear_address(self, address: str) -> None:
        addr = self.destringify_address(address)

        # Check if address is in the correct range
        assert addr[0] == 253
        assert addr[1] == 255
        assert addr[2] == 64
        
        with self.lock:
            next_addr = fps.mongo_get_next_fps_ip_v6()

            # Ensure that the given address is actually before the next address from the pool
            assert self.compare_addresses(addr, next_addr)

            fps.mongo_free_fps_address_to_cache_v6(addr)

    def _increase_address(self, addr: List[int]) -> List[int]:
        # convert subnet portion of addr to int and increase by one
        addr_int = int.from_bytes(addr[6:16], byteorder='big')
        addr_int += 1

        # reconvert new address part to bytearray and concatenate it with the network part of addr
        # will raise RuntimeError if address space is exhausted
        try:
            new_addr = addr_int.to_bytes(10, byteorder='big')
            new_addr = addr[0:6] + list(new_addr)
            
            # Verify the address is still in fdff:4000::/21 subnet
            # First 21 bits should be: fdff:4000
            if new_addr[0] != 253 or new_addr[1] != 255 or new_addr[2] != 64:
                raise OverflowError("Address would be outside fdff:4000::/21 subnet")
                
            return new_addr
        except OverflowError:
            raise RuntimeError("Exhausted FPS IPv6 address space")