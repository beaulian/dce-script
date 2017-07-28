#!/usr/bin/env python
# coding: utf-8
import re
import time
import urlparse
import requests
import schedule

from utils import *
from multiprocessing import Pool, Lock

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOCK = Lock()


# env
dce_ip = decode_env('DCE_IP', required=True)
dce_username = decode_env('DCE_USERNAME', required=True)
dce_password = decode_env('DCE_PASSWORD', required=True)
polling_interval = to_int(decode_env('POLLING_INTERVAL', required=False, default=60))
quota = {
    'LimitCPU': to_int(decode_env('LIMIT_CPU', required=False, default=0)),
    'LimitMemory': to_int(decode_env('LIMIT_MEMORY', required=False, default=0))
}

# utility class or function
self_requests = Requests(auth=(dce_username, dce_password))
url_for = lambda path: urlparse.urljoin('https://' + dce_ip, path)


def check_team(account_name):
    teams = self_requests.get(url_for('/api/teams')).json()
    if account_name not in [team['Name'] for team in teams]:
        r1 = self_requests.post(url_for('/api/teams'), json={'Name': account_name})
        if r1.status_code != 201:
            log_http_error(r1, "create team")

        team = r1.json()
        team['Members'].append(account_name)

        r2 = self_requests.patch(url_for('/api/teams/' + team['Id']), json=team)
        if r2.status_code != 200:
            log_http_error(r2, "add member to team")


def check_tenant(account_name):
    tenants = self_requests.get(url_for('/api/tenants')).json()
    if account_name not in [tenant['Name'] for tenant in tenants]:
        r1 = self_requests.post(url_for('/api/tenants'), json={'Name': account_name})
        if r1.status_code != 201:
            log_http_error(r1, "create tenant")
        if not (quota['LimitCPU'] or quota['LimitMemory']):
            r2 = self_requests.put(url_for('/api/tenants/{}/quota'.format(account_name)), json=quota)
            if r2.status_code != 200:
                log_http_error(r2, "update quota")


def check_mirror_space(account_name):
    def ensure_name(name):
        if '@' in name:
            name = name.split('@', 1)[0]

        invalid_pattern = re.compile(r'^(-|_).*|.*(-|_)$|[^a-z0-9_-]|.*(-|_){2,}.*')
        if invalid_pattern.match(name):
            # replace char except [a-z0-9]
            name = re.sub(r'[\WA-Z_]', '', name)

        return name

    name = ensure_name(account_name)
    mirror_spaces = self_requests.get(url_for('/api/registries/buildin-registry/namespaces')).json()
    if name not in [mirror_space['Name'] for mirror_space in mirror_spaces]:
        r1 = self_requests.post(url_for('/api/registries/buildin-registry/namespaces'),
                            json={
                                    "AccessibleList": [],
                                    "Scopes": [
                                        "namespace:write",
                                        "namespace:privileged",
                                        "namespace:read"
                                    ],
                                    "ShortDescription": None,
                                    "Name": name,
                                    "Visibility": True
                            }
        )
        if r1.status_code != 201:
            log_http_error(r1, "create mirror space")
        teams = self_requests.get(url_for('/api/teams')).json()
        team = filter(lambda x: x['Name'] == account_name, teams)[0]
        r2 = self_requests.post(url_for('/api/registries/buildin-registry/namespaces/{}/accessible-list'.format(name)),
                            json={
                                "TeamId": team['Id'],
                                "Role": "full_control"
                            }
        )
        if r2.status_code != 201:
            log_http_error(r2, "create accessible-list")
        r3 = self_requests.patch(url_for('/api/registries/buildin-registry/namespaces/' + name),
                             json={"Visibility": False})
        if r3.status_code != 201:
            log_http_error(r3, "modify visibility")


def do_check_pipeline(account_name):
    LOG.info('start check user %s...' % account_name)

    LOG.info('start check team...')
    check_team(account_name)

    LOG.info('start check tenant...')
    check_tenant(account_name)

    LOG.info('start check mirror space...')
    check_mirror_space(account_name)

    LOG.info('check user %s success.' % account_name)


def clean_up():
    mirror_spaces = self_requests.get(url_for('/api/registries/buildin-registry/namespaces')).json()
    mirror_names = [mirror_space['Name'] for mirror_space in mirror_spaces]
    for name in mirror_names:
        if name.endswith('@ccfccb.cn'):
            r = self_requests.delete(url_for('/api/registries/buildin-registry/namespaces/' + name))
            if r.status_code != 200:
                log_http_error(r, "delete mirror space", kill=False)
                continue
            LOG.info('delete mirror space %s success.' % name)
    LOG.info('delete mirror spaces success.')


def start_check_process_pool():
    # only run once
    if LOCK.acquire(block=False):
        clean_up()

    r1 = self_requests.get(url_for('/api/accounts'))
    if r1.status_code != 200:
        log_http_error(r1, "get accounts")

    data = r1.json()
    accounts = map(lambda x: x['Name'], data['Data'])

    processes = min(10, len(accounts))

    LOG.info('start create %d processes to run jobs' % processes)
    pool = Pool(processes)
    pool.map(do_check_pipeline, accounts)
    pool.close()
    pool.join()


def main():
    LOG.info('start scheduling, run job every %d seconds' % polling_interval)
    schedule.every(polling_interval).seconds.do(start_check_process_pool)

    while True:
        schedule.run_pending()
        time.sleep(1)


if __name__ == '__main__':
    main()
