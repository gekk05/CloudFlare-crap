import psutil
import json
import time
import requests
import shutil
import os


cf_email = os.environ.get("cf_email")
cf_apikey = os.environ.get("cf_apikey")
zone_id = os.environ.get("zone_id")
headers = {"X-Auth-Email": cf_email, "X-Auth-Key": cf_apikey, "Content-Type": "application/json"}
rules = []
FW_RULE_FILTER_ID = ""
FWFILTER_ID = ""


def check_cpu():
    usage_percentage = int(psutil.cpu_percent())
    sec_level = get_security_level()
    if usage_percentage >= 75 and sec_level != "under_attack":
        print("Enabling safe mode")
        enable_am()
    elif usage_percentage >= 50 and usage_percentage < 75 and sec_level != "High":
        enable_second_highest_sec()
        print("CPU usage getting higher, enablign next level : %{}".format(usage_percentage))
    elif usage_percentage <= 50 and sec_level != "medium":
        print("Reverting back to default security settings")
        enable_medium_sec()
    else:
        print("Normal CPU usage: %{}\nCurrent CloudFlare security level: [{}]".format(usage_percentage, sec_level))

def enable_second_highest_sec():
    body =  {"value": "High"}
    requests.patch("https://api.cloudflare.com/client/v4/zones/{}/settings/security_level".format(zone_id), data=body)
    print("CloudFlare attack mode has been enabled: {}".format(time.asctime(time.localtime())))

def enable_medium_sec(): #default
    body =  {"value": "Medium"}
    requests.patch("https://api.cloudflare.com/client/v4/zones/{}/settings/security_level".format(zone_id), data=body)
    print("CloudFlare attack mode has been enabled: {}".format(time.asctime(time.localtime())))

def enable_am():
    body =  {"value": "under_attack"}
    requests.patch("https://api.cloudflare.com/client/v4/zones/{}/settings/security_level".format(zone_id), data=body)
    print("CloudFlare attack mode has been enabled: {}".format(time.asctime(time.localtime())))

def get_security_level():
    r = requests.get("https://api.cloudflare.com/client/v4/zones/{}/settings/security_level".format(zone_id),headers=headers).json()
    return r["result"]["value"]

#####
# Filters must be created before they are added to rules.
# Listing the filters is needed to append them during update requests
#
#####

def ban_ip(ip):
    # grab current rules, then append to it i
    rules = requests.get("https://api.cloudflare.com/client/v4/zones/{}/firewall/rules?id={}&per_page=25".format(zone_id, FW_RULE_FILTER_ID), headers=headers).json()
    new_rule = "(ip.src eq {})".format(ip)
    if new_rule in rules["result"][0]["filter"]["expression"].split(" or "):
        print("Bad IP {} found in rules".format(ip))
    else:
        rules["result"][0]["filter"]["expression"] += " or {}".format(new_rule) #rules["result"][0]["filter"]["expression"] + new_rule
        data = '[{"id":"%s","action":"block","priority": 0 ,"paused":false,"description":"Script Firewall","expression":"%s","paused":false,"description":"Restrict access from these browsers on this address range."}]' % (FWFILTER_ID,rules["result"][0]["filter"]["expression"].replace('"', '\\"'))
        r = requests.put("https://api.cloudflare.com/client/v4/zones/{}/filters".format(zone_id), headers=headers, data=data)
        print(r.text)
        print("Added new rule: {}".format(new_rule))


def analyze_traffic():
    ips = []
    user_agents = {}
    shutil.copyfile("/var/log/apache2/access.log", "/var/log/apache2/access.log.bak")
    with open("/var/log/apache2/access.log", "r+") as log_file:
        for line in (log_file.readlines() [-2000:]):
            x = line.split(" ")
            ua = line.split('"')[5]
            ip = x[0]
            if ip != "::1":
                if ip in user_agents:
                    user_agents[ip].append(ua)
                else:
                    user_agents.update({ip:[ua]})
        log_file.truncate(0)
        log_file.close()

    for i in user_agents:
        unique_agents = len(list(set(user_agents[i])))
        if unique_agents > 5:
            print("Too many user-agents used ({}). Blocking {}".format(unique_agents, i))

# Count the number of requests per IP
    for ip in list(set(ips)):
       if ips.count(ip) > 200:
            print("Possible attack detected. {} requests within 5 minuts. Blocking {}".format(ips.count(ip), ip))
            ban_ip(ip)

def check_auth():
    pass


def main():

    while(True):
        check_cpu()
        analyze_traffic()
        time.sleep(60)


main()
