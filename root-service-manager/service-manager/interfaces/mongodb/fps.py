from .requests import _mongo_ip_operation
from .validators import validate_fps_ipv6
from .requests import OP_GET_FROM_CACHE, OP_FREE_TO_CACHE, OP_GET_NEXT, OP_UPDATE_NEXT
from .requests import ADDR_FPS, IP_V6

# ....... FPS IP ........#
#########################

def mongo_get_fps_address_from_cache_v6():
    """
    Pop an available FPS address, if any, from the free addresses cache
    @return: int[16] in the shape [253, 255, 64, a, b, c, d, e, f, g, h, i, j, k, l, m]
             equal to [fdff:4000::]"""
    return _mongo_ip_operation(OP_GET_FROM_CACHE, ADDR_FPS, IP_V6)

def mongo_free_fps_address_to_cache_v6(address):
    """
    Add back a FPS address to the cache
    @param address: int[16] in the shape [253, 255, 64, a, b, c, d, e, f, g, h, i, j, k, l, m]
    """
    return _mongo_ip_operation(OP_FREE_TO_CACHE, ADDR_FPS, IP_V6, address, [validate_fps_ipv6])

def mongo_get_next_fps_ip_v6():
    """
    Returns the next available ip address from the FPS addressing space fdff:4000::/21
    @return: int[16] in the shape [253, 255, 64, a, b, c, d, e, f, g, h, i, j, k, l, m]
    """
    return _mongo_ip_operation(OP_GET_NEXT, ADDR_FPS, IP_V6)

def mongo_update_next_fps_ip_v6(address):
    """
    Update the value for the next FPS ip available
    @param address: int[16] in the form [253, 255, 64, a, b, c, d, e, f, g, h, i, j, k, l, m] 
        monotonically increasing with respect to the previous address
    """
    return _mongo_ip_operation(OP_UPDATE_NEXT, ADDR_FPS, IP_V6, address, [validate_fps_ipv6])

