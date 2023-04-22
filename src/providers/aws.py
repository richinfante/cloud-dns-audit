from typing import Iterable
import boto3
from lib import CloudIPOwnership, CloudIPResource, DNSHostDiscovery, DNSRecord

"""
A generator that yields CloudIPOwnership objects for all EC2 Instance public IPs in the given AWS account
"""
def get_ec2_instance_ips(session: boto3.Session) -> Iterable[CloudIPResource]:
  client = session.client('ec2')
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


"""
A generator that yields CloudIPOwnership objects for all EC2 Elastic IP addresses in the given AWS account
"""
def get_ec2_cloud_ips(session: boto3.Session) -> Iterable[CloudIPResource]:
  client = session.client('ec2')
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

"""
A generator that yields CloudIPOwnership objects for all cloudfront distributions in the given AWS account
"""
def get_aws_cloudfront(session: boto3.Session) -> Iterable[CloudIPResource]:
  client = session.client('cloudfront')
  try:
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
  except KeyError:
    pass


"""
A generator that yields CloudIPOwnership objects for all API Gateway domains in the given AWS account
"""
def get_api_gateways(session: boto3.Session):
  client = session.client('apigateway')
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

"""
A generator that yields CloudIPOwnership objects for all Global Accelerator endpoints in the given AWS account
"""
def get_aws_globalaccelerator(session: boto3.Session):
  try:
    client = session.client('globalaccelerator', region_name='us-west-2')  # note: US-WEST-2 is required for this API to work
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
  except Exception:
    pass

"""
A generator that yields CloudIPOwnership objects for all Elastic Load Balancers in the given AWS account
"""
def get_aws_elb(session: boto3.Session) -> Iterable[CloudIPResource]:
  client = session.client('elbv2')
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

"""
A generator that yields CLoudIPOwnership objects for all DNS validation records for ACM certificates
"""
def get_acm_validation_records(session: boto3.Session) -> Iterable[CloudIPResource]:
  client = session.client('acm')
  for certificate in client.list_certificates()['CertificateSummaryList']:
    cert_details = client.describe_certificate(CertificateArn=certificate['CertificateArn'])
    for validation_record in cert_details['Certificate']['DomainValidationOptions']:
      if validation_record['ValidationStatus'] == 'SUCCESS':
        yield CloudIPResource(
          ip_address=None,  # don't need this for DNS validation
          hostname=validation_record['ResourceRecord']['Value'].lower().rstrip('.'),
          resource_type='acm',
          resource_id=certificate['CertificateArn'],
          raw_resource=validation_record,
          region=None,
          tags={}
        )

"""
A generator that yields DNSHostDiscovery objects for all Route53 records that match the given domain name
We use this as part of domain discovery to find any the subdomains that are hosted in Route53
"""
def get_aws_dns_resources(session: boto3.Session, domain_name: str) -> Iterable[DNSHostDiscovery]:
  client = session.client('route53')
  for zone in client.list_hosted_zones()['HostedZones']:
    for record in client.list_resource_record_sets(HostedZoneId=zone['Id'])['ResourceRecordSets']:
      record_dns_name = record['Name'].lower().rstrip('.')
      if record['Type'] in ['A', 'AAAA', 'CNAME'] and record_dns_name.endswith(domain_name):
        yield DNSHostDiscovery(record_dns_name)

"""
Returns a list of all AWS cloud resources that are associated with the given AWS account
We specify account via a boto3 session object
"""
def load_aws_cloud_resources(session: boto3.Session):
    aws_cloud_resources = []

    # add resources
    aws_cloud_resources.extend(get_ec2_instance_ips(session))
    aws_cloud_resources.extend(get_aws_cloudfront(session))
    aws_cloud_resources.extend(get_aws_elb(session))
    aws_cloud_resources.extend(get_ec2_cloud_ips(session))
    aws_cloud_resources.extend(get_aws_globalaccelerator(session))
    aws_cloud_resources.extend(get_api_gateways(session))
    aws_cloud_resources.extend(get_acm_validation_records(session))

    return aws_cloud_resources