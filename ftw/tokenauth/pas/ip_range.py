from ipaddress import ip_address
from ipaddress import ip_network


class InvalidIPRangeSpecification(ValueError):
    """
    """


def parse_ip_range(ip_range):
    try:
        network = ip_network(ip_range)
    except ValueError as exc:
        raise InvalidIPRangeSpecification(exc.message)
    return network


def permitted_ip(client_ip, ip_range):
    try:
        allowed_networks = parse_ip_range(ip_range)
    except InvalidIPRangeSpecification:
        # TODO: Maybe log this? Might help in debugging
        return None

    return ip_address(client_ip) in allowed_networks
