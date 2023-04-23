from typing import List
import dns.resolver
from lib import DNSRecord

"""
Resolve a hostname to a list of DNSRecord objects

For purposes of this tool, we exclusively resolve A, AAAA, and CNAME records.
There are other records that may contain IP addresses (MX records for example),
we ignore them since we're focusing on public web servers / cloud resources.
"""
def resolve_hostname(target, no_cname=False) -> List[DNSRecord]:
  out = []
  for rec_type in ["CNAME", "A", "AAAA"]:
    try:
      # resolve the hostname using DNS
      answers = dns.resolver.resolve(target, rec_type)

      # iterate over answers we got back from the DNS server
      for rdata in answers:
        # A record - IPv4 address
        if rec_type == "A":
          out.append(DNSRecord(ip_address=rdata.to_text(), dns_hostname=target, record_type=rec_type))

        # AAAA record - IPv6 address
        elif rec_type == "AAAA":
          out.append(DNSRecord(ip_address=rdata.to_text(), dns_hostname=target, record_type=rec_type))

        # CNAME record - canonical name that points to another hostname
        # if there is a CNAME record, we don't want to resolve anything else
        # above, we always try resolving CNAMES first, so we can stop here
        # If we continue, we'll get the IP addresses for the CNAME target which are usually
        # internal AWS IPs.
        elif rec_type == "CNAME" and not no_cname:
          # do not resolve anything past a CNAME - it's just going to route to AWS internal IPs.
          return [DNSRecord(target_hostname=rdata.to_text().rstrip('.'), dns_hostname=target, record_type=rec_type)]

    except dns.resolver.NoAnswer:
      pass  # ignore no answers

    except Exception as err:
      print('DNS Error:', type(err), err)

  return out

"""
Helper - resolve a hostname to a list of IP addresses
"""
def resolve_ips(hostname) -> List[str]:
  recs = resolve_hostname(hostname, no_cname=True)
  return [x.ip_address for x in recs if x.ip_address is not None]


