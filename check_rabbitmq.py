#!/usr/bin/env python
#
# check_rabbitmq.py

"""A program for remotely checking the health of RabbitMQ instance. Requires
   the management API available."""

from optparse import OptionParser
import sys
import urllib
import urllib2
import base64
import math

try:
    import json
except ImportError:
    # simplejson can be used with Python 2.4
    import simplejson as json

PLUGIN_VERSION = "0.1.1"

class RabbitAPIChecker(object):
    """Performs checks against the RabbitMQ API and returns the results"""

    # Nagios status codes (Nagios expects one of these to be returned)
    STATE_OK = 0
    STATE_WARNING = 1
    STATE_CRITICAL = 2
    STATE_UNKNOWN = 3

    def __init__(self, hostname, username, password, port=15672):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.port = port

    def check_triggered_alarm(self, args):
        """Checks the node for a triggered alarm"""

        alarm = args[0]
        node = args[1]

        url = "http://%s:%s/api/nodes/%s" % (self.hostname, self.port, node)
        result = self.fetch_from_api(url)

        try:
            if result[alarm]:
                message = "CRITICAL - %s triggered for %s" % (alarm, node)
                state_code = self.STATE_CRITICAL
            else:
                message = "OK - %s is not triggered for %s" % (alarm, node)
                state_code = self.STATE_OK
        except KeyError:
            message = "UNKNOWN - %s is not a valid alarm for %s" % (alarm, node)
            state_code = self.STATE_UNKNOWN

        return (message, state_code)

    def check_sockets(self, args, critical=90, warning=80):
        """Checks the percentage of sockets used"""

        node = args[1]
        url = "http://%s:%s/api/nodes/%s" % (self.hostname, self.port, node)
        result = self.fetch_from_api(url)

        per_sockets_used = math.ceil(
            100 * float(result['sockets_used']) / result['sockets_total'])

        if per_sockets_used >= critical:
            message = "CRITICAL - %d%% of sockets in use" % per_sockets_used
            state_code = self.STATE_CRITICAL
        elif per_sockets_used >= warning:
            message = "WARNING - %d%% of sockets in use" % per_sockets_used
            state_code = self.STATE_WARNING
        else:
            message = "OK - %d%% of sockets in use" % per_sockets_used
            state_code = self.STATE_OK

        return (message, state_code)

    def check_fd(self, args, critical=90, warning=80):
        """Checks the percentage of file descriptors used"""

        node = args[1]
        url = "http://%s:%s/api/nodes/%s" % (self.hostname, self.port, node)
        result = self.fetch_from_api(url)

        per_fd_used = math.ceil(
            100 * float(result['fd_used']) / result['fd_total'])

        if per_fd_used >= critical:
            message = "CRITICAL - %d%% of file descriptors in use" % per_fd_used
            state_code = self.STATE_CRITICAL
        elif per_fd_used >= warning:
            message = "WARNING - %d%% of file descriptors in use" % per_fd_used
            state_code = self.STATE_WARNING
        else:
            message = "OK - %d%% of file descriptors in use" % per_fd_used
            state_code = self.STATE_OK

        return (message, state_code)

    def check_nodes(self, args=None, critical=2, warning=1):
        """ Checks if all nodes on the cluster are running"""

        if len(args) > 1:
            return ("UNKNOWN - Unexpected arguments found", self.STATE_UNKNOWN)

        url = "http://%s:%s/api/nodes" % (self.hostname, self.port)
        results = self.fetch_from_api(url)

        nodes_not_running = []
        message = "OK - All nodes are running"
        state_code = self.STATE_OK

        for node in results:
            if not node['running']:
                nodes_not_running.append(node['name'])

        if len(nodes_not_running) >= critical:
            message = "CRITICAL - Found nodes not running (%s)" % (
                ", ".join(nodes_not_running))
            state_code = self.STATE_CRITICAL
        elif len(nodes_not_running) >= warning:
            message = "WARNING - Found nodes not running (%s)" % (
                ", ".join(nodes_not_running))
            state_code = self.STATE_WARNING

        return (message, state_code)

    def check_aliveness(self, args):
        """Executes an aliveness test on a specified vhost"""

        # Encodes the specified vhost. Needed when vhost specified is /
        vhost = args[1]
        vhost_encoded = urllib.quote_plus(vhost)

        url = "http://%s:%s/api/aliveness-test/%s" % (
            self.hostname, self.port, vhost_encoded)

        results = self.fetch_from_api(url)

        if results['status'] != 'ok':
            message = "CRITICAL - Aliveness Test failed for vhost '%s'" % vhost
            state_code = self.STATE_CRITICAL
        else:
            message = "OK - Aliveness Test passed for vhost '%s'" % vhost
            state_code = self.STATE_OK

        return (message, state_code)


    def fetch_from_api(self, url):
        """Calls the API and processes the JSON result."""
        request = urllib2.Request(url)
        base64string = base64.encodestring(
            '%s:%s' % (self.username, self.password)).replace('\n', '')
        request.add_header("Authorization", "Basic %s" % base64string)

        http_result = urllib2.urlopen(request)

        json_result = json.load(http_result)
        http_result.close()
        return json_result


def main():
    """Main entry point for program"""
    usage = "%prog [options] -H|--hostname HOST ACTION"
    parser = OptionParser(usage=usage,
                          version="%prog "+PLUGIN_VERSION)
    parser.add_option(
        "-u", "--username", default="guest",
        help="Username with monitoring access. Default: guest")
    parser.add_option(
        "-p", "--password", default="guest",
        help="Password for user with monitoring access Default: guest")
    parser.add_option(
        "-P", "--port", default=15672,
        help="Port to run the API checks against Default: 15672")
    parser.add_option("-H", "--hostname", help="Host to check. REQUIRED")
    parser.add_option("-c", "--critical", type="int", help="Critical level")
    parser.add_option("-w", "--warning", type="int", help="Warning level")

    (options, args) = parser.parse_args()

    # Check for required arguments
    if len(args) < 1 or options.hostname == None:
        parser.print_usage()
        return RabbitAPIChecker.STATE_UNKNOWN

    checker = RabbitAPIChecker(options.hostname, options.username,
                               options.password, options.port)

    # Define actions available, will be found in args[0]
    actions = {'mem_alarm': checker.check_triggered_alarm,
               'disk_free_alarm': checker.check_triggered_alarm,
               'check_sockets': checker.check_sockets,
               'check_fd': checker.check_fd,
               'check_nodes': checker.check_nodes,
               'check_aliveness': checker.check_aliveness}

    try:
        if options.critical and options.warning:
            (message, state_code) = actions[args[0]](
                args[0:], options.critical, options.warning)
        elif options.critical:
            (message, state_code) = actions[args[0]](args[0:], options.critical)
        elif options.warning:
            (message, state_code) = actions[args[0]](
                args[0:], warning=options.warning)
        else:
            (message, state_code) = actions[args[0]](args[0:])
    except KeyError:
        print "UNKNOWN - %s is not a valid action" % args[0]
        return RabbitAPIChecker.STATE_UNKNOWN
    except (urllib2.HTTPError, urllib2.URLError), exception:
        print "CRITICAL - %s" % exception
        return RabbitAPIChecker.STATE_CRITICAL
    except IndexError:
        print "UNKNOWN - %s requires one or more options" % args[0]
        return RabbitAPIChecker.STATE_UNKNOWN

    print message
    return state_code

if __name__ == "__main__":
    sys.exit(main())
