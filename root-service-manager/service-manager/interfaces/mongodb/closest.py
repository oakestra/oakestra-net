from .requests import _mongo_ip_operation
from .validators import validate_closest_ipv6
from .requests import OP_GET_FROM_CACHE, OP_FREE_TO_CACHE, OP_GET_NEXT, OP_UPDATE_NEXT
from .requests import ADDR_CLOSEST, IP_V6

# ....... Closest IPv6 ........#
################################

def mongo_get_closest_address_from_cache_v6():
    """
    Pop an available Closest address, if any, from the free addresses cache
    @return: int[16] in the shape [253, 255, 16, a, b, c, d, e, f, g, h, i, j, k, l, m]
             equal to [fdff:1000::]"""
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_CLOSEST, IP_V6)

def mongo_free_closest_address_to_cache_v6(address):
    """
    Add back a Closest address to the cache
    @param address: int[16] in the shape [253, 255, 16, a, b, c, d, e, f, g, h, i, j, k, l, m]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_CLOSEST, IP_V6, address, [validate_closest_ipv6])

def mongo_get_next_closest_ip_v6():
    """
    Returns the next available ip address from the Closest addressing space fdff:1000::/21
    @return: int[16] in the shape [253, 255, 16, a, b, c, d, e, f, g, h, i, j, k, l, m]
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_CLOSEST, IP_V6)

def mongo_update_next_closest_ip_v6(address):
    """
    Update the value for the next Closest ip available
    @param address: int[16] in the form [253, 255, 16, a, b, c, d, e, f, g, h, i, j, k, l, m] 
        monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_CLOSEST, IP_V6, address, [validate_closest_ipv6])

