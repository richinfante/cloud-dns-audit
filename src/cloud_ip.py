import json
import re
from functools import lru_cache
from lib import CloudIPOwnership
from typing import Iterable

"""
This block defines regular expressions to match public AWS hostnames for resources in each service.
The regexes are used to classify hostnames to services during detection.

If a CNAME record value matches one of these regexes, it is considered to be pointing to a cloud resource.
"""
AWS_SERVICES = {
  'ec2': [
    re.compile(r'.+?\.compute-\d\.amazonaws\.com'),
    re.compile(r'.+?\.compute\.amazonaws\.com'),
  ],
  'elb': [
    re.compile(r'.+?\.elb.amazonaws.com')
  ],
  'cloudfront': [
    re.compile(r'.+?\.cloudfront\.net'),
  ],
  'apigateway': [
    re.compile(r'.+?\.execute-api\..+?\.amazonaws\.com')
  ],
  'globalaccelerator': [
    re.compile(r'.+?\.awsglobalaccelerator\.com')
  ],
  'acm': [
    re.compile(r'.+?\.acm-validations\.amazonaws\.com'),
    re.compile(r'.+?\.acm-validations\.aws')
  ],
  'generic': [
    re.compile(r'.+?\.amazonaws.com')
  ]
}

"""
Classify a hostname to a cloud provider and service.

Returns a list of tuples of (provider, service) for the hostname.
"""
def classify_cloud_hostname(hostname):
  out = []
  for (service, regexes) in AWS_SERVICES.items():
    for regex in regexes:
      if regex.match(hostname):
        out.append(('aws', service))

  return out

"""
Load AWS IP ranges from the JSON file downloaded from https://ip-ranges.amazonaws.com/ip-ranges.json
"""
def load_aws_cloud_resource_blocks() -> Iterable[CloudIPOwnership]:
  file = open('./ip-ranges/aws.json', 'r', encoding='utf8')
  contents = file.read()
  json_contents = json.loads(contents)

  for prefix in json_contents['prefixes']:
    yield CloudIPOwnership(
      provider='aws',
      region=prefix['region'],
      service=prefix['service'],
      ip_cidr_block=prefix['ip_prefix']
    )
  for prefix in json_contents['ipv6_prefixes']:
    yield CloudIPOwnership(
      provider='aws',
      region=prefix['region'],
      service=prefix['service'],
      ip_cidr_block=prefix['ipv6_prefix']
    )

"""
Load Azure IP ranges from the JSON file downloaded from https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519
"""
def load_azure_cloud_resource_blocks() -> Iterable[CloudIPOwnership]:
  file = open('./ip-ranges/azure.json', 'r', encoding='utf8')
  contents = file.read()
  json_contents = json.loads(contents)

  for service in json_contents['values']:
    for prefix in service['properties']['addressPrefixes']:
      yield CloudIPOwnership(
        provider='azure',
        region=service['name'],
        service=service['name'],
        ip_cidr_block=prefix
      )

"""
Static list of local IP blocks that are considered to be cloud resources.
"""
AWS_IP_ADDRESSES = list(load_aws_cloud_resource_blocks())
AZURE_IP_ADDRESSES = list(load_azure_cloud_resource_blocks())

"""
Static list of local IP blocks that are considered to be cloud resources

Generally these should not be included in public DNS records
"""
LOCAL_IP_BLOCKS = [
  CloudIPOwnership(provider='local', region='local', service='local', ip_cidr_block='192.168.0.0/16'),
  CloudIPOwnership(provider='local', region='local', service='local', ip_cidr_block='172.16.0.0/12'),
  CloudIPOwnership(provider='local', region='local', service='local', ip_cidr_block='10.0.0.0/8')
]


""""
Classify an IP address to a cloud provider and service.

Since this is a relatively expensive operation, the results are cached.
We must enumerate each cloud provider's IP blocks and check if the IP is included in each block.
"""
@lru_cache(maxsize=1024)
def classify_cloud_ip(ip):
  classifications = []

  # Check if the IP is in any of the AWS IP blocks
  for aws_ip in AWS_IP_ADDRESSES:
    if aws_ip.is_included(ip):
      classifications.append(aws_ip)

  # Check if the IP is in any of the Azure IP blocks
  for azure_ip in AZURE_IP_ADDRESSES:
    if azure_ip.is_included(ip):
      classifications.append(azure_ip)

  # Check if the IP is in any of the local IP blocks
  for local_ip in LOCAL_IP_BLOCKS:
    if local_ip.is_included(ip):
      classifications.append(local_ip)

  return classifications
