from .requests import _mongo_ip_operation
from .validators import validate_underutilized_ipv6, validate_ipv6_length
from .requests import OP_GET_FROM_CACHE, OP_FREE_TO_CACHE, OP_GET_NEXT, OP_UPDATE_NEXT
from .requests import ADDR_UNDERUTILIZED, IP_V6

# ....... Underutilized IP ........#
####################################

def mongo_get_underutilized_address_from_cache_v6():
    """
    Pop an available Underutilized address, if any, from the free addresses cache
    @return: int[16] in the shape [253, 255, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
             equal to [fdff:3000::]
    """
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_UNDERUTILIZED, IP_V6)

def mongo_free_underutilized_address_to_cache_v6(address):
    """
    Add back an Underutilized address to the cache
    @param address: int[16] in the shape [253, 255, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_UNDERUTILIZED, IP_V6, address, [validate_underutilized_ipv6])

def mongo_get_next_underutilized_ip_v6():
    """
    Returns the next available ip address from the Underutilized addressing space fdff:3000::/24
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_UNDERUTILIZED, IP_V6)

def mongo_update_next_underutilized_ip_v6(address):
    """
    Update the value for the next Underutilized ip available
    @param address: int[16] in the form [253, 255, 48, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_UNDERUTILIZED, IP_V6, address, [validate_ipv6_length])