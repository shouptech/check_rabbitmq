#!/usr/bin/env python
#
# check_rabbitmq.py

"""A program for remotely checking the health of RabbitMQ instance. Requires
   the management API available."""

from optparse import OptionParser
import sys
import urllib2
import base64

try:
    import json
except ImportError:
    # simplejson can be used with Python 2.4
    import simplejson as json

PLUGIN_VERSION = "0.1"

# Nagios status codes (Nagios expects one of these to be returned)
STATE_OK = 0
STATE_WARNING = 1
STATE_CRITICAL = 2
STATE_UNKNOWN = 3

class RabbitAPIChecker(object):
    """Performs checks against the RabbitMQ API and returns the results"""

    def __init__(self, hostname, username, password, port=15672):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port

    def memory_alarm(self, node):
        """Calls the API and checks if a high memory alarm has been
           triggerred."""
        url = "http://%s:%s/api/nodes/%s" % (self.hostname, self.port, node)
        result = self.fetch_from_api(url)

        if 'mem_alarm' in result:
            if result['mem_alarm']:
                print "CRITICAL - Memory alarm triggered for %s" % node
                exit(STATE_CRITICAL)
            else:
                print "OK - Memory alarm not triggered for %s" % node
                exit(STATE_OK)
        else:
            print "UNKNOWN - mem_alarm not found in results from API"
            exit(STATE_UNKNOWN)

    def fetch_from_api(self, url):
        """Calls the API and processes the JSON result."""
        request = urllib2.Request(url)
        base64string = base64.encodestring(
            '%s:%s' % (self.username, self.password)).replace('\n', '')
        request.add_header("Authorization", "Basic %s" % base64string)

        try:
            http_result = urllib2.urlopen(request)
        except urllib2.HTTPError, exception:
            print "UNKNOWN - %s" % exception
            exit(STATE_UNKNOWN)

        json_result = json.load(http_result)
        http_result.close()
        return json_result

def main():
    """Main entry point for program"""
    usage = "%prog [options] -H|--hostname HOST ACTION"
    parser = OptionParser(usage=usage,
                          version="%prog "+PLUGIN_VERSION)
    parser.add_option("-u", "--username", default="guest",
                      help="Username with monitoring access")
    parser.add_option("-p", "--password", default="guest",
                      help="Password for user with monitoring access")
    parser.add_option("-P", "--port", default=15672,
                      help="Port to run the API checks against")
    parser.add_option("-H", "--hostname",
                      help="Host to check")
    (options, args) = parser.parse_args()

    # Check for required arguments
    if len(args) < 1 or options.hostname == None:
        parser.print_usage()
        exit(STATE_UNKNOWN)

    checker = RabbitAPIChecker(options.hostname, options.username,
                               options.password, options.port)

    if args[0] == 'mem_alarm':
        # Check if high memory alarm has been triggered
        if len(args) < 2:
            sys.stderr.write("Action mem_alarm requires a NODE\n")
            exit(STATE_UNKNOWN)
        checker.memory_alarm(args[1])

if __name__ == "__main__":
    main()
