# Validator functions

# ....... Length Validators ........#
####################################

def validate_ipv4_length(address):
    assert len(address) == 4
    for n in address:
        assert 0 <= n < 256

def validate_ipv6_length(address):
    assert len(address) == 16
    for n in address:
        assert 0 <= n < 256

# ....... Service IPv4 ........#
################################

def validate_service_ipv4(address):
    validate_ipv4_length(address)
    assert address[0] == 10
    assert address[1] == 30

def validate_service_ipv4_cache(address):
    assert len(address) == 4
    for n in address:
        assert 0 <= n < 254

# ....... Service IPv6 ........#
################################

def validate_service_ipv6(address):
    validate_ipv6_length(address)
    assert address[0] == 253
    assert address[1] == 255
    assert address[2] == 0 or address[2] == 8

# ....... Closest IPv6 ........#
################################

def validate_closest_ipv6(address):
    validate_ipv6_length(address)
    assert address[0] == 253
    assert address[1] == 255
    assert address[2] == 16
    assert 0 <= address[3] < 8

# ....... Underutilized IPv6 ........#
####################################

def validate_underutilized_ipv6(address):
    validate_ipv6_length(address)
    assert address[0] == 253
    assert address[1] == 255
    assert address[2] == 48
    assert 0 <= address[3] < 8

# ....... Round Robin IPv6 ........#
####################################

def validate_rr_ipv6(address):
    validate_ipv6_length(address)
    assert address[0] == 253
    assert address[1] == 255
    assert address[2] == 32
    assert 0 <= address[3] < 8

# ........ FPS IPv6 ........#
#############################

def validate_fps_ipv6(address):
    validate_ipv6_length(address)
    assert address[0] == 253
    assert address[1] == 255
    assert address[2] == 64
    assert 0 <= address[3] < 8

# ....... Subnet ........#
################################

def validate_subnet_ipv4(address):
    validate_ipv4_length(address)
    assert address[0] == 10
    assert 17 < address[1] < 30

def validate_subnet_ipv6(address):
    validate_ipv6_length(address)
    assert 252 <= address[0] <= 253