import requests
from lib import DNSHostDiscovery

"""
Enumerate subdomains using certspotter.com API

This returns a list of DNSHostDiscovery objects that can be used to
"""
def ct_domain_enum(domain_name, api_key=None):
  headers={}
  # use api key if found
  if api_key:
    headers['Authorization'] = f'Bearer {api_key}'

    # call certspotter API to get all issuances
  certs = requests.get(
    f'https://api.certspotter.com/v1/issuances?domain={domain_name}&include_subdomains=true&match_wildcards=true&expand=issuer&expand=dns_names',
    headers=headers,
    timeout=10
  )

  # load json response
  cert_info = certs.json()

  # if error code, print and exit
  if not certs.ok:
    print(f"Error Searching Cert. Logs: Code {cert_info.get('code')}: {cert_info.get('message')}")
    exit(1)

  # Add discovered hosts to targets set to avoid duplicates
  out_certs = set()
  for target in cert_info:
    for dns_name in target['dns_names']:
      out_certs.add(dns_name)

  # convert to DNSHostDiscovery objects
  out = []
  for cert_name in out_certs:
    out.append(DNSHostDiscovery(cert_name))

  return out