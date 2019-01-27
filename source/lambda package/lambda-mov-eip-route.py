


import logging
import os
from botocore.exceptions import ClientError

import boto3




# Read Environment Variables for Tags
# All TAGS should have a tag-name of 'tag_key_name'
# The primary firewall should have a tag-value of 'pri_fw_tag_key_value'
# The primary firewall should have a tag-value of 'sec_fw_tag_key_value'

# tag_key_name = os.environ['tag_key_name']
# prifw_tag_key_value = os.environ['prifw_tag_key_value']
# secfw_tag_key_value = os.environ['secfw_tag_key_value']
# int_index_number = os.environ['int_index_number']


event = {}
context = {}

ec2 = boto3.resource('ec2')

ec2_c = boto3.client('ec2')
client = boto3.client('ec2')
events_client = boto3.client('events')
logger = logging.getLogger()
logger.setLevel(logging.INFO)

secfw = {}
prifw = {}
preempt = 'yes'


def replace_vpc_route_to_fw(route_table_id, destination_cidr_block, NetworkInterfaceId, DryRun=False):
    ec2 = boto3.client('ec2')

    try:
        ec2.delete_route(
        DestinationCidrBlock=destination_cidr_block,
        RouteTableId=route_table_id
        )
    except ClientError as e:
        logger.info("Got error {0} deleting route Moving on.".format(e))
        return None

    try:
        resp = ec2.create_route(
            DryRun=False,
            DestinationCidrBlock=destination_cidr_block,
            RouteTableId=route_table_id,
            NetworkInterfaceId=NetworkInterfaceId
        )
    except ClientError as e:
        logger.info("Got error {0} adding route Moving on.".format(e))
        return None
    return resp



def failover(route_table_id, failed_eni, backup_eni):
    ec2_client = boto3.client('ec2')
    route_table = ec2_client.describe_route_tables(RouteTableIds=['rtb-007153a803f3b5bab'])
    Interfaceids = []
    routes = route_table['RouteTables'][0]['Routes']
    for route in routes:
        key = 'NetworkInterfaceId'
        if key in route:
            eni1 = route['NetworkInterfaceId']
            if route['NetworkInterfaceId'] == failed_eni:
                destination_cidr_block = route['DestinationCidrBlock']
                replace_vpc_route_to_fw(route_table_id, destination_cidr_block, backup_eni, DryRun=False)



def get_firewall_status():
    global prifw
    global secfw
    tag_key_name = 'fw-ha-status'
    secfw_tag_key_value = 'def-route-primary'
    prifw_tag_key_value = 'inter-vpc-primary'
    int_index_number = 1


    logger.info('[INFO] Got event{}'.format(event))
    logger.info("tag_key_name: {}".format(tag_key_name))
    logger.info("prifw_tag_key_value: {}".format(prifw_tag_key_value))
    logger.info("secfw_tag_key_value: {}".format(secfw_tag_key_value))
    logger.info("Interface that pubip will be associated with is eth{}".format(int_index_number))

    # create filter for instances in running state
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]

    eiptagged = [
        {
            'Name': 'tag-key',
            'Values': [tag_key_name]

        }
    ]
    # filter the instances based on filters() above
    instances = ec2.instances.filter(Filters=eiptagged)

    VPNInstances = []
    logger.info("got these instances with the expected tags: {}".format(instances))

    for instance in instances:
        # for each instance, append to array
        VPNInstances.append(instance.id)
        logger.info("processing instance: {}".format(instance))
        for tag in instance.tags:
            if tag["Value"] == secfw_tag_key_value:
                secfw["instance"] = instance
                secfw["association"] = ec2.NetworkInterfaceAssociation(instance.id)
                logger.info("Found VPN secondaryfw instance.id via TAG value secondaryfw: {}".format(instance.id))
            elif tag["Value"] == prifw_tag_key_value:
                prifw["instance"] = instance
                prifw["association"] = ec2.NetworkInterfaceAssociation(instance.id)
                logger.info("Found VPN primaryfw instance.id via TAG value primaryfw: {}".format(instance.id))

    logger.info('[INFO] Primary firewall is {}'.format(prifw))
    logger.info('[INFO] Primary firewall is {}'.format(secfw))
    association = ec2.NetworkInterfaceAssociation('instance.id')





def lambda_handler(event, context):
    global gcontext
    route_table_id = 'rtb-007153a803f3b5bab'
    fw1_trust_eni = 'eni-07a25e7ed03d8173a'
    fw2_trust_eni = 'eni-07f4cfaa13efe17a2'
    vpc_summary_route = '10.0.0.0/8'
    def_route = '0.0.0.0/0'

    get_firewall_status()

    global prifw
    global secfw

    prifwstatus = prifw["instance"].state['Name']
    logger.info("Primary firewall running status: {}".format(prifwstatus))
    secfwstatus = secfw["instance"].state['Name']
    logger.info("Secondart firewall running status: {}".format(secfwstatus))







    if ((prifwstatus == 'running') and (secfwstatus == 'running')):
        if preempt == 'no':
            logger.info("Both firewalls running - exiting and we cannot failback")
            exit()
        else:
            replace_vpc_route_to_fw(route_table_id, vpc_summary_route, fw2_trust_eni, DryRun=False)
            replace_vpc_route_to_fw(route_table_id, def_route, fw1_trust_eni, DryRun=False)

    elif ((prifwstatus != 'running') and (secfwstatus == 'running')):
        try:
            failover(route_table_id, fw1_trust_eni, fw2_trust_eni)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))

    elif ((prifwstatus == 'running') and (secfwstatus != 'running')):
        try:
            failover(route_table_id, fw2_trust_eni, fw1_trust_eni)
        except Exception as e:
            logger.info("Disassociation Fail [RESPONSE]: {}".format(e))



if __name__ == '__main__':
    event = {}
    context = {}
    lambda_handler(event, context)
