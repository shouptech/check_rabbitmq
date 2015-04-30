# check_rabbitmq.py

check_rabbitmq.py returns status messages for use in Nagios monitoring.

## Requirements
Requires a Python interpreter. Tested to work with 2.4.x and above. If using 2.4.x, you'll need the simplejson package. Doesn't work with Python 3.

## Usage

    usage: check_rabbitmq.py [options] -H|--hostname HOST ACTION

    options:
      --version             show program's version number and exit
      -h, --help            show this help message and exit
      -u USERNAME, --username=USERNAME
                            Username with monitoring access. Default: guest
      -p PASSWORD, --password=PASSWORD
                            Password for user with monitoring access Default: guest
      -P PORT, --port=PORT  Port to run the API checks against Default: 15672
      -H HOSTNAME, --hostname=HOSTNAME
                            Host to check. REQUIRED
      -c CRITICAL, --critical=CRITICAL
                            Critical level
      -w WARNING, --warning=WARNING
                            Warning level

## Actions

The script can perform the following actions

### mem_alarm

Checks if the high memory usage alarm has been triggered on specified node. Requires an additional argument which matches the node name in the cluster.

    check_rabbitmq.py -H rmqhost mem_alarm rabbit@rmqhost

### disk_free_alarm

Checks if the high disk usage alarm has been triggered on specified node. Requires an additional argument which matches the node name in the cluster.

    check_rabbitmq.py -H rmqhost disk_free_alarm rabbit@rmqhost

### check_sockets

Checks for the percentage of sockets in use. Default critical threshold is 90% and default warning threshold is 80%. Specify alternate thresholds with -c/-w.

Check socket usage with default thresholds:

    check_rabbitmq.py -H rmqhost check_sockets rabbit@rmqhost

Check socket usage with critical threshold of 95% and warning threshold of 90%:

    check_rabbitmq.py -c 95 -w 90 -H rmqhost check_sockets rabbit@rmqhost

### check_fd

Checks for the percentage of file descriptors in use. Default critical threshold is 90% and default warning threshold is 80%. Specify alternate thresholds with -c/-w.

Check file descriptor usage with default thresholds:

    check_rabbitmq.py -H rmqhost check_fd rabbit@rmqhost

Check file descriptor usage with critical threshold of 95% and warning threshold of 90%:

    check_rabbitmq.py -c 95 -w 90 -H rmqhost check_fd rabbit@rmqhost

### check_nodes

Checks that all nodes in the cluster are running. Default critical threshold is 2 nodes not running. Default warning threshold is 1 node not running. Specify alternate thresholds with -c/-w.

    check_rabbitmq.py -H rmqhost check_nodes
