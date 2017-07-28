#!/usr/bin/env python
#-*- coding: utf-8 -*-

import os
import json
import argparse
import functools


def raise_error(text):
    print "error: ", text
    os._exit(0)


try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    raise_error("please install 'requests' module first")


class _requests_without_verify(object):
    def __getattr__(cls, key):
        return functools.partial(getattr(requests, key), verify=False)

requests_without_verify = _requests_without_verify()


class http_request(object):
    def __init__(self, args):
        self.args = args
        self.req_url = "https://" + args.ipaddr
        if self.req_url.endswith("/"):
            self.req_url = self.req_url[:-1]

    def get(self):
        if self.args.username and self.args.password:
            resp = requests_without_verify.get(self.req_url + "/services",
                                auth=(self.args.username, self.args.password))
        else:
            resp = requests_without_verify.get(self.req_url + "/services")
        resp.encoding = "utf-8"
        return resp.json()

    def create(self, data):
        resp = requests_without_verify.post(self.req_url + "/services/create",
                             auth=(self.args.username, self.args.password),
                             json=data, verify=False)
        if resp.status_code != 201 or resp.status_code != 200:
            return resp.text
        return ''


def save(args):
    if args.file is None:
        base_dir = "/usr/local/var/lib/docker/dump"
        if not os.path.exists(base_dir):
            try:
                os.makedirs(base_dir)
            except OSError as e:
                raise_error(e)
        path = os.path.join(base_dir, "services.json")
    else:
        path = args.file
    data = http_request(args).get()
    with open(path, "w") as f:
        f.write(json.dumps(map(lambda s: s["Spec"], data), indent=4))
    print "save done."


def restore(args):
    path = args.file
    if not os.path.exists(path):
        raise_error("the file does not exist")
    with open(path, "r") as f:
        try:
            data = json.loads(f.read())
        except ValueError as e:
            raise_error(e)
        ret = map(http_request(args).create, data)
        info = "".join(list(set(ret))).strip()
        if info:
            raise_error(info)
    print "restore done."


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--save", help="back services up", action="store_true")
    parser.add_argument("-r", "--restore", help="restore services to docker", action="store_true")
    parser.add_argument("-f", "--file",  help="the path to store services, \
                                         default /usr/local/var/lib/docker/dump/services.json")
    parser.add_argument("-u", "--username", help="the username of DCE")
    parser.add_argument("-p", "--password", help="the password of DCE")
    parser.add_argument("-i", "--ipaddr", help="the ip of DCE")
    args = parser.parse_args()

    if args.ipaddr is None:
        raise_error("--ipaddr is necessary")
    if args.save and args.restore:
        raise_error("--save and --restore can use at once")
    if args.restore and not (args.username and args.password and args.file):
        raise_error("--file and --username and --password are necessary")

    if args.save:
        save(args)
    elif args.restore:
        restore(args)


if __name__ == '__main__':
    main()
