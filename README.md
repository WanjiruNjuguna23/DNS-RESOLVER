#  DNS Resolver from Scratch

A recursive DNS resolver built in Python using UDP sockets and raw DNS packet construction.

##  How It Works
- Starts from root DNS servers
- Recursively follows NS referrals
- Parses A record from the final authoritative server

##  Getting Started

```bash
python dns_resolver.py
