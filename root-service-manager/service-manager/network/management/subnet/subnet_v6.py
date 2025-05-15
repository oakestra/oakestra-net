import threading
import ipaddress
from typing import List

from interfaces.mongodb import subnet
from network.management.strategy import IPAddressStrategy


class IPv6SubnetStrategy(IPAddressStrategy):
    """IPv6 subnet address allocation strategy"""
    
    def __init__(self):
        self.lock = threading.Lock()

    def validate_custom_address(self, address: str, job_name: str) -> bool:
        # Not implemented for subnets as they're not user-assignable
        return False

    def get_next_address(self) -> str:
        with self.lock:
            addr = subnet.mongo_get_subnet_address_from_cache_v6()

            if addr is None:
                addr = subnet.mongo_get_next_subnet_ip_v6()
                next_addr = self._increase_address(addr)
                # change bytes array to int array
                subnet.mongo_update_next_subnet_ip_v6(list(next_addr))

            return self.stringify_address(addr)

    def clear_address(self, address: str) -> None:
        addr = self.destringify_address(address)

        # Check if address is in the correct rage
        assert 252 <= addr[0] < 254
        for n in addr[1:15]:
            assert 0 <= n < 256

        with self.lock:
            next_addr = subnet.mongo_get_next_subnet_ip_v6()

            # Ensure that the give address is actually before the next address from the pool
            assert self._compare_addresses(addr, next_addr)

            subnet.mongo_free_subnet_address_to_cache_v6(addr)

    def _increase_address(self, addr: List[int]) -> List[int]:
        # convert subnet portion of addr to int and increase by one
        addr_int = int.from_bytes(addr[0:15], byteorder='big')
        addr_int += 1

        # reconvert new subnet part to bytearray and right pad it with 0 to length 16
        new_subnet = addr_int.to_bytes(15, byteorder='big')
        new_subnet += bytes(16 - (len(new_subnet) % 16))

        if new_subnet[0] == 253 and new_subnet[1] == 254:
            # if the first 16 bits are fdfd, we reached the limit of worker subnetworks
            # fc00::/120 is the first available subnetwork
            # fdfd:ffff:ffff:ffff:ffff:ffff:ffff:ff00/120 is the last available subnetwork
            # fdfe::/16 is reserved for future use
            raise RuntimeError("Exhausted IPv6 Address Space for workers")

        return new_subnet

    def _compare_addresses(self, addr1: List[int], addr2: List[int]) -> bool:
        addr1_str = ''.join(str(x) for x in addr1[0:15])
        addr2_str = ''.join(str(x) for x in addr2[0:15])
        return int(addr1_str) < int(addr2_str)

    def stringify_address(self, addr: List[int]) -> str:
        return str(ipaddress.ip_address(bytes(addr)))

    def destringify_address(self, addr_str: str) -> List[int]:
        addr = []
        # get long notation of IPv6 addrstr
        for num in ipaddress.ip_address(addr_str).exploded.split(":"):
            addr.append(int(num[0:2], 16))
            addr.append(int(num[2:4], 16))
        return addr
