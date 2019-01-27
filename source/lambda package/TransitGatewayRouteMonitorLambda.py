# Copyright (c) 2018, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Justin Harris <jharris@paloaltonetworks.com>

"""
Palo Alto Networks TransitGatewayRouteMonitorLambda.py

Script triggered by a Cloudwatch event that will monitor the health of the firewalls
via the "show chassis status" op command on the Trust interface.
The purpose is to assess the health of the firewall and modifiy the route AWS route table to redirect traffic if the
firewall is down.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
"""

import logging
import os
import ssl
import urllib
import xml.etree.ElementTree as et

import boto3
from botocore.exceptions import ClientError

secfw = {}
prifw = {}

event = {}
context = {}
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

ec2 = boto3.resource('ec2')

ec2_client = boto3.client('ec2')
client = boto3.client('ec2')
events_client = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

def check_for_split_routes(route_table_id, vpc_summary_route, def_route):
    """
    Checks the route table if split routes is True and both VPC Summary and Default point to the same eni
    Return False else Return True
    :param route_table_id:
    :param vpc_summary_route:
    :param def_route:

    :param route_table_id: route table the we need to check
    :return: True/False

    """
    vpc_summary_route_eni = ''
    def_route_eni = ''
    route_table = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
    Interfaceids = []
    routes = route_table['RouteTables'][0]['Routes']
    for route in routes:
        key = 'NetworkInterfaceId'
        if key in route:
            eni1 = route['NetworkInterfaceId']
            if route['DestinationCidrBlock'] == vpc_summary_route:
                vpc_summary_route_eni = eni1
            elif route['DestinationCidrBlock'] == def_route:
                def_route_eni = eni1
    if vpc_summary_route_eni == def_route_eni:
        return False
    else:
        return True

def replace_vpc_route_to_fw(route_table_id, destination_cidr_block, NetworkInterfaceId, DryRun=False):
    """
    Scan the route table for blackhole routes where the next hop is the NIC of the failed firewall
    Delete any routes that are either Default routes or a summary route of all the spoke VPC's
    Add new routes for hte default and vpc summary route where the next hop is NetworkIntefaceId

    :param route_table_id: The route table that requires modification
    :param destination_cidr_block: The cidr block that we need to change.  Normally the default route and VPC summary route
    :param NetworkInterfaceId: The eni of the Firewall that we need to failover to
    :param DryRun: Perform a DryRun - Doesn't update the route table
    :return: Respone to route_create or 'None'

    """

    try:
        ec2_client.delete_route(
            DestinationCidrBlock=destination_cidr_block,
            RouteTableId=route_table_id
        )
        logger.info("Success deleting {0} route".format(destination_cidr_block))
    except ClientError as e:
        logger.info("Got error {0} deleting route Moving on.".format(e))
        return None

    try:
        resp = ec2_client.create_route(
            DryRun=False,
            DestinationCidrBlock=destination_cidr_block,
            RouteTableId=route_table_id,
            NetworkInterfaceId=NetworkInterfaceId
        )
        logger.info("Success adding {} route next hop {}".format(destination_cidr_block, NetworkInterfaceId))
    except ClientError as e:
        logger.info("Got error {0} adding route Moving on.".format(e))
        return None
    return resp


def failover(route_table_id, failed_eni, backup_eni):
    """

    :param route_table_id:
    :param failed_eni:
    :param backup_eni:
    :return:
    Looks for routes that are blackholed by the failure of the firewall
    When it finds a route it call replance_vpc_route_to_fw to update the next hop to a functional eni

    :param route_table_id: The route table that requires modification
    :param failed_eni: NetworkInterfaceId: The eni of the Firewall that has failed
    :param backup_eni: NetworkInterfaceId: The eni of the Firewall that we need to failover to
    :return:
    """


    route_table = ec2_client.describe_route_tables(RouteTableIds=[route_table_id])
    Interfaceids = []
    routes = route_table['RouteTables'][0]['Routes']
    for route in routes:
        key = 'NetworkInterfaceId'
        if key in route:
            eni1 = route['NetworkInterfaceId']
            if route['NetworkInterfaceId'] == failed_eni:
                logger.info("Found route {} with blackhole next hop {}".format(failed_eni,
                            route['DestinationCidrBlock']))
                destination_cidr_block = route['DestinationCidrBlock']
                replace_vpc_route_to_fw(route_table_id, destination_cidr_block, backup_eni, DryRun=False)


def get_firewall_status(gwMgmtIp, api_key):
    """
     Reruns the status of the firewall.  Calls the op command show chassis status
     Requires an apikey and the IP address of the interface we send the api request
     :param gwMgmtIp:
     :param api_key:
     :return:
     """

    global gcontext
    # cmd = urllib.request.Request('https://google.com')
    cmd = urllib.request.Request(
        "https://" + gwMgmtIp + "/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=" + api_key)
    # Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command: {}'.format(cmd))
    try:
        response = urllib.request.urlopen(cmd, data=None, context=gcontext, timeout=5).read()
        logger.info(
            "[INFO]:Got http 200 response from FW with address {}. So need to check the response".format(gwMgmtIp))
        # Now we do stuff to the gw
    except urllib.error.URLError:
        logger.info("[INFO]: No response from FW with address {}. So maybe not up!".format(gwMgmtIp))
        return 'down'
        # sleep and check again?
    else:
        logger.info("[INFO]: FW is responding!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'down'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got response header error for the command")
        return 'down'

    if resp_header.attrib['status'] == 'success':
        # The fw responded with a successful command execution
        for element in resp_header:
            if element.text.rstrip() == 'yes':
                # Call config gw command?
                logger.info("[INFO]: FW with ip {} is ready ".format(gwMgmtIp))
                return 'running'
    else:
        return 'down'


def lambda_handler(event, context):

    preempt = os.environ['preempt']
    vpc_summary_route = os.environ['VpcSummaryRoute']
    fw1_trust_eni = os.environ['fw1Trusteni']
    fw2_trust_eni = os.environ['fw2Trusteni']
    route_table_id = os.environ['fromTGWRouteTableId']
    fw1_trust_ip = os.environ['fw1Trustip']
    fw2_trust_ip = os.environ['fw2Trustip']
    api_key = os.environ['apikey']
    split_routes = os.environ['splitroutes']

    def_route = '0.0.0.0/0'

    check_for_split_routes(route_table_id, vpc_summary_route, def_route)

    # fw1_trust_eni = 'eni-09539d453383a172a'
    # fw2_trust_eni = 'eni-04fe20fe0f4f3f374'

    global gcontext

    prifwstatus = get_firewall_status(gwMgmtIp=fw1_trust_ip, api_key=api_key)
    secfwstatus = get_firewall_status(gwMgmtIp=fw2_trust_ip, api_key=api_key)

    if (split_routes) == 'yes':
        def_route_nic = fw1_trust_eni
        vpc_summary_nic = fw2_trust_eni
    else:
        def_route_nic = fw1_trust_eni
        vpc_summary_nic = fw1_trust_eni

    if ((prifwstatus == 'running') and (secfwstatus == 'running')):
        if preempt == 'no':
            logger.info("Both firewalls running - exiting and we cannot failback")
            exit()
        else:
            """
            Call split_routes to check if we need to modify routes so that both firewalls are securing 
            traffic.  If split_routes == True but check_for_split_routes returns False then we need to failback
            
            """
            if split_routes == 'yes':
                if check_for_split_routes(route_table_id, vpc_summary_route, def_route) == False:
                    logger.info("Both firewalls running and we can failback")

                    replace_vpc_route_to_fw(route_table_id, vpc_summary_route, vpc_summary_nic, DryRun=False)
                    replace_vpc_route_to_fw(route_table_id, def_route, def_route_nic, DryRun=False)

    elif ((prifwstatus != 'running') and (secfwstatus == 'running')):
        try:
            failover(route_table_id, fw1_trust_eni, fw2_trust_eni)
            logger.info("Failing over all routes to firewall 2")

        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))

    elif ((prifwstatus == 'running') and (secfwstatus != 'running')):
        logger.info("Failing over all routes to firewall 1")
        try:
            failover(route_table_id, fw2_trust_eni, fw1_trust_eni)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))


if __name__ == '__main__':
    event = {}
    context = {}
    lambda_handler(event, context)
