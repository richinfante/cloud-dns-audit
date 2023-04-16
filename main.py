import argparse
import boto3
import argparse
import json
from typing import Iterable, List
import requests
import dns.resolver
import ipaddress
import re
import tqdm
from functools import lru_cache

from colorama import init as colorama_init
from colorama import Fore, Style

colorama_init()

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
  'generic': [
    re.compile(r'.+?\.amazonaws.com')
  ]
}

def classify_cloud_hostname(hostname):
  out = []
  for (service, regexes) in AWS_SERVICES.items():
    for regex in regexes:
      if regex.match(hostname):
        out.append(('aws', service))

  return out

class CloudIPResource:
  def __init__(self, ip_address, hostname, resource_type, resource_id, tags, region, raw_resource):
    self.ip_address = ip_address
    self.hostname = hostname.lower() if hostname else None
    self.resource_type = resource_type
    self.resource_id = resource_id
    self.raw_resource = raw_resource
    self.tags = tags
    self.region = region

  def __str__(self):
    return f'<CloudIPResource resource_type={self.resource_type} ip={self.ip_address} host={self.hostname} resource_id={self.resource_id}>'


class CloudIPOwnership:
  def __init__(self, provider, region, service, ip_cidr_block):
    self.provider = provider
    self.region = region
    self.service = service
    self.ip_cidr_block = ip_cidr_block

  def __str__(self):
    return f'<CloudIPOwnership provider={self.provider} region={self.region} service={self.service} ip_cidr_block={self.ip_cidr_block}>'

  def is_included(self, ip) -> bool:
    if ip is None:
      return False

    net_obj = ipaddress.ip_network(self.ip_cidr_block)
    ip_obj = ipaddress.ip_address(ip)

    return ip_obj in net_obj

class DNSRecord:
  def __init__(self, dns_hostname, ip_address = None, target_hostname=None, record_type=None):
    self.target_hostname = target_hostname
    self.ip_address = ip_address
    self.dns_hostname = dns_hostname.lower() if dns_hostname else None
    self.record_type = record_type

  def __str__(self):
    if self.target_hostname:
      return f'<DNS:{self.record_type} {self.dns_hostname} => {self.target_hostname}>'
    else:
      return f'<DNS:{self.record_type} {self.dns_hostname} => {self.ip_address}>'


class DNSHostDiscovery:
  def __init__(self, dns_hostname):
    self.dns_hostname = dns_hostname

  def __str__(self):
    return f'<DNSHostDiscovery {self.dns_hostname}>'

  def __eq__(self, other):
    if not isinstance(other, type(self)):
        return False
    # all instances of this class are considered equal to one another
    return other.dns_hostname == self.dns_hostname

  def __hash__(self):
    return self.dns_hostname.__hash__()

  def __lt__(self, other):
    return self.dns_hostname < other.dns_hostname



def get_ec2_instance_ips() -> Iterable[CloudIPResource]:
  client = boto3.client('ec2')
  for resource in client.describe_instances()['Reservations']:
    for instance in resource['Instances']:
      # skip non public ones, nothing to check there.
      if 'PublicIpAddress' not in instance and 'PublicDnsName' not in instance:
        continue

      # no public info, skip
      if not instance.get('PublicIPAddress') and not instance.get('PublicDnsName'):
        continue

      yield CloudIPResource(
        ip_address=instance['PublicIpAddress'] if 'PublicIpAddress' in instance else None,
        hostname=instance['PublicDnsName'] if 'PublicDnsName' in instance else None,
        resource_type='ec2',
        resource_id=instance['InstanceId'],
        raw_resource=instance,
        region=instance['Placement']['AvailabilityZone'],
        tags=instance.get('Tags') or {}
      )


def load_aws_cloud_resource_blocks():# -> Iterable[CloudIPOwnership]:
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

def load_azure_cloud_resource_blocks():# -> Iterable[CloudIPOwnership]:
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

AWS_IP_ADDRESSES = list(load_aws_cloud_resource_blocks())
AZURE_IP_ADDRESSES = list(load_azure_cloud_resource_blocks())
LOCAL_IP_BLOCKS = [
  CloudIPOwnership(provider='local', region='local', service='local', ip_cidr_block='192.168.0.0/16'),
  CloudIPOwnership(provider='local', region='local', service='local', ip_cidr_block='172.16.0.0/12'),
  CloudIPOwnership(provider='local', region='local', service='local', ip_cidr_block='10.0.0.0/8')
]

@lru_cache(maxsize=1024)
def classify_cloud_ip(ip):
  for aws_ip in AWS_IP_ADDRESSES:
    if aws_ip.is_included(ip):
      return aws_ip

  for azure_ip in AZURE_IP_ADDRESSES:
    if azure_ip.is_included(ip):
      return azure_ip

  for local_ip in LOCAL_IP_BLOCKS:
    if local_ip.is_included(ip):
      return local_ip

  return None

def get_ec2_cloud_ips() -> Iterable[CloudIPResource]:
  client = boto3.client('ec2')
  for resource in client.describe_addresses()['Addresses']:
    if 'NetworkInterfaceId' in resource:
      eni = client.describe_network_interfaces(NetworkInterfaceIds=[resource['NetworkInterfaceId']])['NetworkInterfaces'][0]
      hostname = eni['Association']['PublicDnsName']
    else:
      hostname = None

    yield CloudIPResource(
      ip_address=resource['PublicIp'],
      hostname=hostname,
      resource_type='ec2',
      resource_id=resource.get('InstanceId') or resource.get('NetworkInterfaceId'),
      raw_resource=resource,
      region=resource['NetworkBorderGroup'],
      tags=resource.get('Tags') or {}
    )

def get_aws_cloudfront() -> Iterable[CloudIPResource]:
  client = boto3.client('cloudfront')
  for resource in client.list_distributions()['DistributionList']['Items']:

    yield CloudIPResource(
      ip_address=None, # TODO: list ip addresses here
      hostname=resource['DomainName'].lower(),
      resource_type='cloudfront',
      resource_id=resource['Id'],
      raw_resource=resource,
      region=None,
      tags={}
    )

def get_api_gateways():
  client = boto3.client('apigateway')
  for resource in client.get_domain_names()['items']:
    yield CloudIPResource(
      ip_address=None, # TODO: list ip addresses here
      hostname=resource['regionalDomainName'].lower(),
      resource_type='apigateway',
      resource_id=resource['domainName'],
      raw_resource=resource,
      region=None,
      tags={}
    )

def get_aws_globalaccelerator():
  client = boto3.client('globalaccelerator', region_name='us-west-2')  # note: US-WEST-2 is required for this API to work
  for accelerator in  client.list_accelerators()['Accelerators']:
    for ip_set in accelerator['IpSets']:
      for ip_addr in ip_set['IpAddresses']:
        yield CloudIPResource(
        ip_address=ip_addr,
        hostname=accelerator['DnsName'].lower(),
        resource_type='globalaccelerator',
        resource_id=accelerator['AcceleratorArn'],
        raw_resource=accelerator,
        region=None,
        tags={}
      )

def get_aws_elb() -> Iterable[CloudIPResource]:
  client = boto3.client('elbv2')
  for resource in client.describe_load_balancers()['LoadBalancers']:
    yield CloudIPResource(
      ip_address=None,
      hostname=resource['DNSName'].lower(),
      resource_type='elb',
      resource_id=resource['LoadBalancerArn'],
      raw_resource=resource,
      region=None,
      tags={}
    )


def ct_domain_enum(domain_name, api_key=None):
  headers={}
  # use api key if found
  if api_key:
    headers['Authorization'] = f'Bearer {api_key}'

    # call certspotter API to get all issuances
  certs = requests.get(f'https://api.certspotter.com/v1/issuances?domain={domain_name}&include_subdomains=true&match_wildcards=true&expand=issuer&expand=dns_names', headers=headers, timeout=10)
  cert_info = certs.json()
  if not certs.ok:
    print(f"Error: {cert_info.get('code')}: {cert_info.get('message')}")
    exit(1)

  # Add discovered hosts to targets
  out_certs = set()
  for target in cert_info:
    for dns_name in target['dns_names']:
      out_certs.add(dns_name)

  out = []
  for cert_name in out_certs:
    out.append(DNSHostDiscovery(cert_name))

  return out

def resolve_hostname(target) -> List[DNSRecord]:
  for rec_type in ["CNAME", "A", "AAAA"]:
    try:
      answers = dns.resolver.resolve(target, rec_type)
      for rdata in answers:
        # print(f"{target} {rdata.to_text()}")

        if rec_type == "A":
          yield DNSRecord(ip_address=rdata.to_text(), dns_hostname=target, record_type=rec_type)
        elif rec_type == "AAAA":
          yield DNSRecord(ip_address=rdata.to_text(), dns_hostname=target, record_type=rec_type)
        elif rec_type == "CNAME":
          yield DNSRecord(target_hostname=rdata.to_text().rstrip('.'), dns_hostname=target, record_type=rec_type)
          return # do not resolve anything past a CNAME - it's just going to route to AWS internal IPs.
          # We'll try to match this to cloud.

    except Exception as err:
      pass # ignore errors
      # print(f"{target} {rec_type}: ERROR: {err}")



if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser()
  arg_parser.add_argument("--sslmate-key", dest='sslmate_api_key', default=None)
  arg_parser.add_argument("--domain", dest='domains', action='append', default=[])
  arg_parser.add_argument('--subdomain-file', dest='subdomain_file', default='subdomains.txt')
  arg_parser.add_argument('--skip-cloud-discovery', dest='skip_cloud_discovery', action='store_true', default=False)
  arg_parser.add_argument('--skip-certificate-discovery', dest='skip_certificate_discovery', action='store_true', default=False)
  args = arg_parser.parse_args()

  print('Enumerating cloud resources...')
  aws_cloud_resources = []
  if not args.skip_cloud_discovery:
    aws_cloud_resources.extend(get_ec2_instance_ips())
    aws_cloud_resources.extend(get_aws_cloudfront())
    aws_cloud_resources.extend(get_aws_elb())
    aws_cloud_resources.extend(get_ec2_cloud_ips())
    aws_cloud_resources.extend(get_aws_globalaccelerator())
    aws_cloud_resources.extend(get_api_gateways())
    print('Found %s AWS cloud resources that are internet facing.' % len(aws_cloud_resources))
  print('Know about %s AWS IP address ranges' % len(AWS_IP_ADDRESSES))
  print('Know about %s Azure IP address ranges' % len(AZURE_IP_ADDRESSES))

  # print()
  # print('CLOUD RESOURCES')
  # print()

  # for resource in aws_cloud_resources:
    # print(resource)
    # classify ip
    # for aws_ip in aws_ips:
    #   if aws_ip.is_included(resource.ip_address):
    #     print('CLASSIFIED: -> ', aws_ip)
    #     break

    # # classify host
    # if resource.hostname:
    #   classified = classify_cloud_hostname(resource.hostname)
    #   if classified:
    #     print('CLASSIFIED DOMAIN: -> ', classified)


  print()
  print('DNS DISCOVERY')
  print()
  for domain in args.domains:
    discovered_hostnames = set()
    if not args.skip_certificate_discovery:
      try:
        discovered_hostnames.update(ct_domain_enum(domain, api_key=args.sslmate_api_key))
        print(f'loaded {len(discovered_hostnames)} subdomains from certificate transparency')
      except Exception as err:
        print("ct error: %s" % err)

    # allow loading domains from dictfile
    if args.subdomain_file:
      dict_file = open(args.subdomain_file, 'r')
      subdomains = dict_file.read().split('\n')
      for subdomain in subdomains:
        subdomain = subdomain.strip().strip('.') # strip leading whitespace, and leading/trailing dots
        if subdomain:
          discovered_hostnames.add(DNSHostDiscovery(f'{subdomain}.{domain}'))

      print(f'loaded {len(subdomains)} subdomains from dictfile')

    tqdmbar = tqdm.tqdm(sorted(discovered_hostnames), desc="DNS Probe [%s]" % domain)
    for host in tqdmbar:
      tqdmbar.set_description(f"DNS Probe [{host.dns_hostname}]")
      # print(f"{Fore.YELLOW}{Style.DIM}Probe DNS: %s{Style.RESET_ALL}" % (host.dns_hostname))
      for dns_record in resolve_hostname(host.dns_hostname):
        print(f"{Fore.GREEN}Discovered DNS Entry {dns_record.record_type} for Domain: %s{Style.RESET_ALL}" % (host.dns_hostname))
        print(f"Record: {dns_record}")
        cloud_ip = None
        cloud_host = None

        # classify ip using cloud ip ranges
        if dns_record.ip_address:
          cloud_ip = classify_cloud_ip(dns_record.ip_address)

        # classify host using regexes for hostnames that are known to be cloud
        elif dns_record.target_hostname:
          cloud_host = classify_cloud_hostname(dns_record.target_hostname)

        matching_resources = []
        for resource in aws_cloud_resources:
          # print("vs: %s and %s" % ((resource.ip_address, dns_record.ip_address), (resource.hostname, dns_record.target_hostname)))
          if resource.ip_address and resource.ip_address == dns_record.ip_address:
            # print("FOUND MATCHING RECORD IN AWS VIA IP: %s", resource)
            matching_resources.append(resource)

          elif resource.hostname and resource.hostname == dns_record.target_hostname:
            matching_resources.append(resource)
            # print("FOUND MATCHING RECORD IN AWS VIA DNSNAME: %s", resource)

        if (cloud_ip or cloud_host) or matching_resources:
          if not matching_resources:
            print(f"{Fore.RED}[!! WARNING] {Style.RESET_ALL} Resource DNS record belonging to %s found that does not belong to your AWS Account: " % (cloud_ip.provider or cloud_host[0][0]), dns_record)
          else:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Matched to resources: ",  ', '.join([str(x) for x in matching_resources]))
        else:
          print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} We did not detect any cloud resources that match this dns entry. It may be a third party vendor. ")




