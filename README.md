# About

## antiddos.py

Extremely simple script that monitors webserver access logs and CPU usage for anomalous behaviors. The script will parse Apache's access logs for a few different patterns classifies as anomalous:

- Multiple user-agents being received from the same source IP address within a short timeframe
- Rate limit on requests at a source IP-level
- Blocking hosting provider ASNs
- Rejecting traffic from countires that don't suit the demographic of my target audience (f.e China; nobody from China realistically has a reason to visit my site).

It is worth nothing that most garbage traffic will be caught by CloudFlare, so the work done by the script will only refine rules to catch traffic/abused that slipped through the cracks. A "global" limit is also implemented via CPU usage monitoring on the machine hosting the webserver. If CPU usage exceeds a certain threshold, the script will increase the security controls by calling CloudFlare APIs automatically. 
