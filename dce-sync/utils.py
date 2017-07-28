# coding=utf-8
import os
import json
import logging
import requests
import functools


__all__ = ['LOG', 'Requests', 'log_http_error', 'decode_env', 'to_int']


logging.basicConfig(level=logging.INFO, format='%(message)s')
LOG = logging.getLogger(__name__)


class Requests(object):
    def __init__(self, auth=None):
        self.auth = auth

    def __getattr__(self, key):
        return functools.partial(getattr(requests, key), verify=False,
                                 auth=self.auth)


def log_error(text, kill=True):
    LOG.exception(text)
    if kill:
        os._exit(1)


def log_http_error(r, text, kill=True):
    log_error("%s failed with status code %s, %s" %
              (text, r.status_code, r.json()['message']), kill=kill)


def decode_env(varname, default=None, required=False):
    if varname not in os.environ and required:
        log_error("environment variable %s missed" % varname)

    value = os.getenv(varname)
    if not value:
        return default

    try:
        return json.loads(value)
    except ValueError:
        return value


def to_int(value):
    if isinstance(value, int):
        return value
    else:
        try:
            value = int(value)
        except Exception as e:
            log_error("invalid value: %s, %s" % (value, str(e)))
        else:
            return value