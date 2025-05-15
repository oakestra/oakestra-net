from abc import ABC, abstractmethod
from typing import List
import threading
import ipaddress

class IPAddressStrategy(ABC):
    """Abstract base class for IP address allocation strategies"""

    @abstractmethod
    def validate_custom_address(self, address: str, job_name: str) -> bool:
        """Validate a custom address provided by user"""
        pass

    @abstractmethod
    def get_next_address(self) -> str:
        """Get the next available address from the pool"""
        pass

    @abstractmethod
    def clear_address(self, address: str) -> None:
        """Return an address to the pool"""
        pass

    @abstractmethod
    def stringify_address(self, addr: List[int]) -> str:
        """Convert internal address representation to string format"""
        pass

    @abstractmethod
    def destringify_address(self, addr_str: str) -> List[int]:
        """Convert string address to internal representation"""
        pass

    @abstractmethod
    def _compare_addresses(self, addr1: List[int], addr2: List[int]) -> bool:
        """Compare two addresses"""
        pass

    @abstractmethod
    def _increase_address(self, addr: List[int]) -> List[int]:
        """Increase the address by one"""
        pass
