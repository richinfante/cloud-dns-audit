import ipaddress

"""
Stores information about a cloud resource that has an IP address or hostname
"""
class CloudIPResource:
  def __init__(self, ip_address, hostname, resource_type, resource_id, tags, region, raw_resource):
    # host & IP
    self.ip_address = ip_address
    self.hostname = hostname.lower() if hostname else None

    # cloud resource info
    self.resource_type = resource_type  # e.g. ec2, cloudfront, etc
    self.resource_id = resource_id  # e.g. instance id, distribution id, etc
    self.raw_resource = raw_resource  # the raw resource object from the cloud provider
    self.tags = tags  # the tags associated with the resource
    self.region = region  # the region the resource is in

  def __str__(self):
    return f'<CloudIPResource resource_type={self.resource_type} ip={self.ip_address} host={self.hostname} resource_id={self.resource_id}>'

"""
Stores information about a block of IP addresses that are owned by a cloud provider

This also contains matching logic to determine if a given IP address is included in the block
"""
class CloudIPOwnership:
  def __init__(self, provider, region, service, ip_cidr_block):
    self.provider = provider  # e.g. aws, gcp, etc
    self.region = region   # e.g. us-east-1, us-west-2, etc
    self.service = service  # e.g. ec2, cloudfront, etc
    self.ip_cidr_block = ip_cidr_block  # e.g. 192.168.1.1/32 (CIDR notation)

  def __str__(self):
    return f'<CloudIPOwnership provider={self.provider} region={self.region} service={self.service} ip_cidr_block={self.ip_cidr_block}>'

  """
  Determines if the given IP address is included in the block of IP addresses owned by this object
  """
  def is_included(self, ip) -> bool:
    if ip is None:
      return False

    net_obj = ipaddress.ip_network(self.ip_cidr_block)
    ip_obj = ipaddress.ip_address(ip)

    return ip_obj in net_obj

"""
A simplified DNS record that contains the hostname, IP address, and type of record it originated from
"""
class DNSRecord:
  def __init__(self, dns_hostname, ip_address = None, target_hostname=None, record_type=None):
    # IP address that the DNS record resolves to
    # this can be ipv4 or ipv6, or None if the record is a CNAME
    self.ip_address = ip_address

    # hostname that the DNS record resolves to
    # this is only set if the record is a CNAME
    self.target_hostname = target_hostname.lower() if dns_hostname else None

    # the hostname that was queried
    self.dns_hostname = dns_hostname.lower() if dns_hostname else None

    # the type of DNS record
    # e.g. A, AAAA, CNAME
    self.record_type = record_type

  def __str__(self):
    if self.target_hostname:
      return f'<DNS:{self.record_type} {self.dns_hostname} => {self.target_hostname}>'
    else:
      return f'<DNS:{self.record_type} {self.dns_hostname} => {self.ip_address}>'

"""
Store information about a DNS hostname that was discovered during a scan

This could be from brute forcing, or from a cert. transparancy log
"""
class DNSHostDiscovery:
  def __init__(self, dns_hostname):
    self.dns_hostname = dns_hostname

  def __str__(self):
    return f'<DNSHostDiscovery {self.dns_hostname}>'

  """
  Check if this object is equal to another instance of DNSHostDiscovery
  """
  def __eq__(self, other):
    if not isinstance(other, type(self)):
        return False
    # all instances of this class are considered equal to one another
    return other.dns_hostname == self.dns_hostname

  """
  Use the contained string as a hash
  """
  def __hash__(self):
    return self.dns_hostname.__hash__()

  """
  Provide sortability for this class
  """
  def __lt__(self, other):
    return self.dns_hostname < other.dns_hostname

