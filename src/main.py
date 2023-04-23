import argparse
import boto3
import argparse
import tqdm

from colorama import init as colorama_init
from colorama import Fore, Style

from providers.aws import load_aws_cloud_resources, get_aws_dns_resources
from lib import DNSHostDiscovery
from cloud_ip import classify_cloud_ip, classify_cloud_hostname, AWS_IP_ADDRESSES, AZURE_IP_ADDRESSES, LOCAL_IP_BLOCKS
from dnsutil import resolve_hostname
from cert_transparency import ct_domain_enum
colorama_init()


if __name__ == "__main__":
  arg_parser = argparse.ArgumentParser()
  arg_parser.add_argument("--sslmate-key", dest='sslmate_api_key', default=None)
  arg_parser.add_argument("--domain", dest='domains', action='append', default=[])
  arg_parser.add_argument("--aws-profile", dest='aws_profile', action='append', default=[])
  arg_parser.add_argument('--subdomain-file', dest='subdomain_file', default='subdomains.txt')
  arg_parser.add_argument('--skip-cloud-discovery', dest='skip_cloud_discovery', action='store_true', default=False)
  arg_parser.add_argument('--skip-certificate-discovery', dest='skip_certificate_discovery', action='store_true', default=False)
  args = arg_parser.parse_args()

  print()
  print('CLOUD RESOURCE DISCOVERY')
  print()
  aws_cloud_resources = []
  if not args.skip_cloud_discovery:
    for profile_name in args.aws_profile or ['default']:
      print("loading resources for profile: %s" % profile_name)
      session = boto3.Session(profile_name=profile_name)
      aws_cloud_resources.extend(load_aws_cloud_resources(session))
      print('Found %s AWS cloud resources that are internet facing (profile %s)' % (len(aws_cloud_resources), profile_name))

  for aws_resource in aws_cloud_resources:
    print(aws_resource)
  print('Know about %s AWS IP address ranges' % len(AWS_IP_ADDRESSES))
  print('Know about %s Azure IP address ranges' % len(AZURE_IP_ADDRESSES))

  print()
  print('DNS DISCOVERY')
  print()
  for domain in args.domains:
    discovered_hostnames = set()
    if not args.skip_certificate_discovery:
      try:
        discovered_hostnames.update(ct_domain_enum(domain, api_key=args.sslmate_api_key))
        print(f'loaded {len(discovered_hostnames)} subdomains from certificate transparency')
        print(','.join([str(x) for x in discovered_hostnames]))
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

    for profile_name in args.aws_profile or ['default']:
      session = boto3.Session(profile_name=profile_name)
      route53_resources = list(get_aws_dns_resources(session, domain))
      discovered_hostnames.update(route53_resources)
      print(f'loaded {len(route53_resources)} subdomains from AWS Route53')
      print(','.join([str(x) for x in route53_resources]))

    tqdmbar = tqdm.tqdm(sorted(discovered_hostnames), desc="DNS Probe [%s]" % domain)
    for host in tqdmbar:
      tqdmbar.set_description(f"DNS Probe [{host.dns_hostname}]")
      # print(f"{Fore.YELLOW}{Style.DIM}Probe DNS: %s{Style.RESET_ALL}" % (host.dns_hostname))

      for dns_record in resolve_hostname(host.dns_hostname):
        print(f"{Fore.GREEN}Discovered DNS Entry {dns_record.record_type} for Domain: %s{Style.RESET_ALL}" % (host.dns_hostname))
        cloud_ips = None
        cloud_host = None

        # classify ip using cloud ip ranges
        if dns_record.ip_address:
          cloud_ips = classify_cloud_ip(dns_record.ip_address)

        # classify host using regexes for hostnames that are known to be cloud
        elif dns_record.target_hostname:
          cloud_host = classify_cloud_hostname(dns_record.target_hostname)

        matching_resources = []
        # find matching resources in our known set of cloud resources
        for resource in aws_cloud_resources:
          if resource.ip_address and resource.ip_address == dns_record.ip_address:
            matching_resources.append(resource)

          elif resource.hostname and resource.hostname == dns_record.target_hostname:
            matching_resources.append(resource)

        # if we have matched this to a cloud resource, or we have classified as a cloud resource
        if (cloud_ips or cloud_host) or matching_resources:
          # if no matching resources, but we have classified as cloud, then we have a problem
          if not matching_resources:
            info_str = 'unknown'
            if cloud_ips:
              info_str = ', '.join(["%s-%s-%s" % (cloud_ip.provider, cloud_ip.region, cloud_ip.service) for cloud_ip in cloud_ips])
            else:
              info_str = '-'.join(cloud_host[0])

            print(f"{Fore.RED}[!! WARNING] {Style.RESET_ALL} Resource DNS record belonging to %s found that does not belong to your AWS Account: " % (info_str), dns_record)

          # if we have matching resources, then this is a valid configuration
          else:
            print(f"{Fore.GREEN}[OK]{Style.RESET_ALL} Matched to resources: ",  ', '.join([str(x) for x in matching_resources]))

        # if not cloud and no resources, print as informational
        # probably a vendor or other service we are using.
        else:
          print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} We did not detect any cloud resources that match this dns entry. It may be a third party vendor. ")




