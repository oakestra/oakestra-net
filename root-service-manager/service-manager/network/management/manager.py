from typing import Optional

from .strategy import IPAddressStrategy
from .service.v4.service import IPv4ServiceStrategy
from .service.v6.instance import IPv6InstanceStrategy
from .service.v6.closest import IPv6ClosestStrategy
from .service.v6.rr import IPv6RRStrategy
from .service.v6.underutilized import IPv6UnderutilizedStrategy
from .service.v6.fps import IPv6FPSStrategy
from .subnet.subnet_v4 import IPv4SubnetStrategy
from .subnet.subnet_v6 import IPv6SubnetStrategy

# Strategy name constants
STRATEGY_IPV4_SERVICE = 'ipv4_service'

STRATEGY_IPV4_SUBNET = 'ipv4_subnet'
STRATEGY_IPV6_SUBNET = 'ipv6_subnet'

# TODO: add new balancing strategies here
STRATEGY_IPV6_INSTANCE = 'ipv6_instance' 
STRATEGY_IPV6_CLOSEST = 'ipv6_closest'
STRATEGY_IPV6_RR = 'ipv6_rr'
STRATEGY_IPV6_UNDERUTILIZED = 'ipv6_underutilized'
STRATEGY_IPV6_FPS = 'ipv6_fps'

class IPAddressManager:
    """Manager for IP address allocation using different strategies"""
    
    def __init__(self):
        self.strategies = {
            STRATEGY_IPV4_SERVICE: IPv4ServiceStrategy(),
            STRATEGY_IPV6_INSTANCE: IPv6InstanceStrategy(),
            STRATEGY_IPV6_CLOSEST: IPv6ClosestStrategy(),
            STRATEGY_IPV6_RR: IPv6RRStrategy(),
            STRATEGY_IPV6_UNDERUTILIZED: IPv6UnderutilizedStrategy(),
            STRATEGY_IPV6_FPS: IPv6FPSStrategy(),
            STRATEGY_IPV4_SUBNET: IPv4SubnetStrategy(),
            STRATEGY_IPV6_SUBNET: IPv6SubnetStrategy(),
        }
        
    def get_strategy(self, strategy_name: str) -> IPAddressStrategy:
        """Get the strategy for a specific IP address type"""
        if strategy_name not in self.strategies:
            raise ValueError(f"Unknown strategy: {strategy_name}")
        return self.strategies[strategy_name]
        
    def new_address(self, strategy_name: str, custom_address: Optional[str] = None, job_name: Optional[str] = None) -> str:
        """Get a new address using the specified strategy"""
        strategy = self.get_strategy(strategy_name)
        
        if custom_address is not None and job_name is not None:
            try:
                if strategy.validate_custom_address(custom_address, job_name):
                    return custom_address
            except Exception as e:
                raise e
                
        return strategy.get_next_address()
        
    def clear_address(self, strategy_name: str, address: str) -> None:
        """Return an address to the pool using the specified strategy"""
        strategy = self.get_strategy(strategy_name)
        strategy.clear_address(address)


# Create a singleton instance
ip_manager = IPAddressManager()