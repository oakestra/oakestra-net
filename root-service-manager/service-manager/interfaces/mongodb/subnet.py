from .requests import _mongo_ip_operation
from .validators import validate_subnet_ipv6, validate_ipv6_length, validate_subnet_ipv4, validate_ipv4_length
from .requests import OP_GET_FROM_CACHE, OP_FREE_TO_CACHE, OP_GET_NEXT, OP_UPDATE_NEXT
from .requests import ADDR_SUBNET, IP_V6, IP_V4

# ....... Subnet v4 ........#
#############################

def mongo_get_subnet_address_from_cache():
    """
    Pop an available Subnet address, if any, from the free addresses cache
    @return: int[4] in the shape [10,x,y,z]
    """
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_SUBNET, IP_V4)

def mongo_free_subnet_address_to_cache(address):
    """
    Add back a subnetwork address to the cache
    @param address: int[4] in the shape [10,30,x,y]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_SUBNET, IP_V4, address, [validate_ipv4_length])

def mongo_get_next_subnet_ip():
    """
    Returns the next available subnetwork ip address from the addressing space 10.16.y.z/12
    @return: int[4] in the shape [10,x,y,z]
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_SUBNET, IP_V4)

def mongo_update_next_subnet_ip(address):
    """
    Update the value for the next subnet ip available
    @param address: int[4] in the form [10,x,y,z] monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_SUBNET, IP_V4, address, [validate_subnet_ipv4])

# ....... Subnet v6 ........#
#############################

def mongo_get_subnet_address_from_cache_v6():
    """
    Pop an available Subnet address, if any, from the free addresses cache
    @return: int[16] in the shape [252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0]
    """
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_SUBNET, IP_V6)

def mongo_free_subnet_address_to_cache_v6(address):
    """
    Add back a subnetwork address to the cache
    @param address: int[16] in the shape [252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ,0]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_SUBNET, IP_V6, address, [validate_ipv6_length])

def mongo_get_next_subnet_ip_v6():
    """
    Returns the next available subnetwork ip address from the addressing space fc00::/7
    @return: int[16] in the shape [25[2-3], a, b, c, d, e, f, g, h, i, j, k, l, m, n, 0] 
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_SUBNET, IP_V6)

def mongo_update_next_subnet_ip_v6(address):
    """
    Update the value for the next subnet ip available
    @param address: int[16] in the form [252, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_SUBNET, IP_V6, address, [validate_subnet_ipv6])