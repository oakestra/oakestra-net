from .requests import _mongo_ip_operation
from .validators import validate_service_ipv4_cache, validate_service_ipv4, validate_service_ipv6
from .requests import OP_GET_FROM_CACHE, OP_FREE_TO_CACHE, OP_GET_NEXT, OP_UPDATE_NEXT
from .requests import ADDR_SERVICE, IP_V4, IP_V6

# Service IPs in IPv4 span over all types in one subnet, contrary to IPv6
# where there is a subnet for each type

# ....... Service IP ........#
##############################

def mongo_get_service_address_from_cache():
    """
    Pop an available Service address, if any, from the free addresses cache
    @return: int[4] in the shape [10,30,x,y]
    """
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_SERVICE, IP_V4)

def mongo_free_service_address_to_cache(address):
    """
    Add back an address to the cache
    @param address: int[4] in the shape [10,30,x,y]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_SERVICE, IP_V4, address, [validate_service_ipv4_cache])

def mongo_get_next_service_ip():
    """
    Returns the next available ip address from the addressing space 10.30.x.y/16
    @return: int[4] in the shape [10,30,x,y,]
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_SERVICE, IP_V4)

def mongo_update_next_service_ip(address):
    """
    Update the value for the next service ip available
    @param address: int[4] in the form [10,30,x,y] monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_SERVICE, IP_V4, address, [validate_service_ipv4])

# ....... Instance IP ........#
###############################

# TODO rename functions and db entries to instance IP for clarity

def mongo_get_service_address_from_cache_v6():
    """
    Pop an available Service address, if any, from the free addresses cache
    @return: int[16] in the shape [253, 255, [0, 8], a, b, c, d, e, f, g, h, i, j, k, l, m]
             equal to [fdff:[00, 08]00::]
    """
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_SERVICE, IP_V6)

def mongo_free_service_address_to_cache_v6(address):
    """
    Add back an address to the cache
    @param address: int[16] in the shape [253, 255, [0, 8], a, b, c, d, e, f, g, h, i, j, k, l, m]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_SERVICE, IP_V6, address, [validate_service_ipv6])

def mongo_get_next_service_ip_v6():
    """
    Returns the next available ip address from the addressing space fdff:ffff:ffff:ffff::/64
    @return: int[16] in the shape [253, 255, [0, 8], a, b, c, d, e, f, g, h, i, j, k, l, m]
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_SERVICE, IP_V6)

def mongo_update_next_service_ip_v6(address):
    """
    Update the value for the next service ip available
    @param address: int[16] in the form [253, 255, [0, 8], a, b, c, d, e, f, g, h, i, j, k, l, m] 
        monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_SERVICE, IP_V6, address, [validate_service_ipv6])