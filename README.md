# cloud-dns-audit

Audit your cloud configuration against DNS records, to validate configuration and detect misconfigurations or dangling records. This tool was developed as part of my Master's capstone project, with the aim to help detect these dangling or misconfigured DNS records.

When EC2 instances are stopped, or other services such as elastic IP or global accelerator release their IPv4 addresses, they are released into a shared pool. Other customers can obtain these, and there is a potential for attackers to systematically create instances in hopes of finding one that is recieving traffic as a result of dangling or misconfigured records. They can use services like Letsencrypt to "validate" ownership via a HTTP-01 challenge, and launch phishing attacks or harvest data using their instance.

## Usage

```bash
python3 src/main.py --aws-profile $AWS_PROFILE --domain $DOMAIN --subdomain-file $SUBDOMAIN_DICT_FILE
```

## Certificate Transparency
For certificate transparency, we use the free SSLMate Certspotter API: https://sslmate.com/ct_search_api/.

You may specify this via the `SSLMATE_API_KEY` environment variable, or via this key via `--sslmate-api-key` argument. Note that using the command line argument will cause it to be listed in system process lists.

## DNS subdomain lists
You can find plenty of subdomain lists via repositories such as the awesome Seclists repo: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
