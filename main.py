import argparse
import boto3
import argparse
import json
from typing import Iterable, List
import requests
import dns.resolver

class CloudIPResource:
  def __init__(self, ip_address, hostname, resource_type, resource_id, tags, region, raw_resource):
    self.ip_address = ip_address
    self.hostname = hostname
    self.resource_type = resource_type
    self.resource_id = resource_id
    self.raw_resource = raw_resource
    self.tags = tags
    self.region = region

  def __str__(self):
    return f'<CloudIPResource ip={self.ip_address} host={self.hostname} resource_type={self.resource_type} resource_id={self.resource_id}>'

class DNSRecord:
  def __init__(self, dns_hostname, ip_address = None, target_hostname=None):
    self.target_hostname = target_hostname
    self.ip_address = ip_address
    self.dns_hostname = dns_hostname

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

  for ip in get_ec2_cloud_ips():
    print(ip)

  for host in ct_domain_enum('veritonic.com'):
    print(host)
    for dns_record in resolve_hostname(host.dns_hostname):
      print(dns_record)




