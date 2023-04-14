import argparse
import boto3
import argparse
import json
from typing import Iterable, List
import requests
import dns.resolver
import ipaddress
import re

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
  'generic': [
    re.compile(r'.+?\.amazonaws.com')
  ]
}

def classify_cloud_hostname(hostname):
  for (service, regexes) in AWS_SERVICES.items():
    for regex in regexes:
      if regex.match(hostname):
        return ('aws', service)

  return None

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
  def __init__(self, dns_hostname, ip_address = None, target_hostname=None):
    self.target_hostname = target_hostname
    self.ip_address = ip_address
    self.dns_hostname = dns_hostname.lower() if dns_hostname else None

  def __str__(self):
    if self.target_hostname:
      return f'<DNSRecord {self.dns_hostname} => {self.target_hostname}>'
    else:
      return f'<DNSRecord {self.dns_hostname} => {self.ip_address}>'


class DNSHostDiscovery:
  def __init__(self, dns_hostname):
    self.dns_hostname = dns_hostname

  def __str__(self):
    return f'<DNSHostDiscovery {self.dns_hostname}>'

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

def get_aws_elb() -> Iterable[CloudIPResource]:
  client = boto3.client('elbv2')
  for resource in client.describe_load_balancers()['LoadBalancers']:

    # client = boto3.client('globalaccelerator')

    yield CloudIPResource(
      ip_address=None, # TODO: list ip addresses here
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
          yield DNSRecord(ip_address=rdata.to_text(), dns_hostname=target)
        elif rec_type == "AAAA":
          yield DNSRecord(ip_address=rdata.to_text(), dns_hostname=target)
        elif rec_type == "CNAME":
          yield DNSRecord(target_hostname=rdata.to_text(), dns_hostname=target)
          return # do not resolve anything past a CNAME - it's just going to route to AWS internal IPs.
          # We'll try to match this to cloud.

    except Exception as err:
      pass # ignore errors
      # print(f"{target} {rec_type}: ERROR: {err}")



if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser()
  args = arg_parser.parse_args()

  aws_ips = list(load_aws_cloud_resource_blocks())

  aws_cloud_resources = []
  aws_cloud_resources.extend(get_aws_cloudfront())
  aws_cloud_resources.extend(get_aws_elb())
  aws_cloud_resources.extend(get_ec2_cloud_ips())

  print()
  print('CLOUD RESOURCES')
  print()

  for resource in aws_cloud_resources:
    print(resource)
    # classify ip
    for aws_ip in aws_ips:
      if aws_ip.is_included(resource.ip_address):
        print('CLASSIFIED: -> ', aws_ip)
        break

    # classify host
    if resource.hostname:
      classified = classify_cloud_hostname(resource.hostname)
      if classified:
        print('CLASSIFIED DOMAIN: -> ', classified)


  print()
  print('DNS DISCOVERY')
  print()
  for host in ct_domain_enum('veritonic.com'):
    print(host)
    for dns_record in resolve_hostname(host.dns_hostname):
      print(dns_record)
      if dns_record.ip_address:
        for aws_ip in aws_ips:
          if aws_ip.is_included(dns_record.ip_address):
            print('CLASSIFIED: -> ', aws_ip)
            break

      elif dns_record.target_hostname:
        classified = classify_cloud_hostname(dns_record.target_hostname)
        if classified:
          print('CLASSIFIED DOMAIN: -> ', classified)




