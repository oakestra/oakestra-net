import socket


def sanitize(address, request=False):
    """
    Sanitizes address to conform with request format.
    Adds brackets if a valid IPv6 address is given and
    the sanitization is for a HTTP request.
    Removes 4to6 mapped address part for valid IPv4 format,
    if a 4to6 mapped IPv4 address is given.
    """
    if is_4to6_mapped(address):
        return extract_v4_address_from_v6_mapped(address)
    if request:
        return add_brackets_if_ipv6(address)
    return address


def is_ipv6(address):
    """Checks if the given address is a valid IPv6 address."""
    try:
        socket.inet_pton(socket.AF_INET6, address)
        return True
    except socket.error:
        return False


def add_brackets_if_ipv6(address):
    """Adds brackets to the address if it's IPv6 and doesn't have them."""
    if is_ipv6(address) and not address.startswith("["):
        return f"[{address}]"
    else:
        return address


def is_4to6_mapped(address):
    """Checks if the given address is 4-to-6 mapped."""
    return is_ipv6(address) and address.startswith("::")


def extract_v4_address_from_v6_mapped(address):
    """Returns IPv4 address, given address is a 4-to-6 mapped IP address"""
    return address.split(":")[3]
