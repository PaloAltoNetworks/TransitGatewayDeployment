"""
Paloaltonetworks TransitGatewayInitialiseLambda.py

Script triggered from a custom resource.  The script performs two funcitons

1) The script will create route table entries in each VPC that use next hop of the
transit gateway attachment.  We use this script today as next hop TransitGatewayId is not supported in CFT yet
When CFT use the updated boto3 libraries we can remove this function and place the route entries using CFT.

2) The script will start a step function that will complete the configuration of the Paloaltonetworks firewalls
Two post deployment tasks are performed by the InitialiseFwlambda.py script associated with the step function

This software is provided without support, warranty, or guarantee.
Use at your own risk.
"""

import logging
import os
import boto3
import cfnresponse
import sys



logger = logging.getLogger()
logger.setLevel(logging.INFO)

defroutecidr = '0.0.0.0/0'
vnetroutecidr = '10.0.0.0/8'


def add_route_tgw_nh(route_table_id, destination_cidr_block, transit_gateway_id):
    """
    Adds a route to a VPC route table with next hop of the TransitGatewayId
    :param route_table_id:
    :param destination_cidr_block:
    :param transit_gateway_id:
    :return:
    """
    ec2 = boto3.client('ec2')

    resp = ec2.create_route(
        DryRun=False,
        RouteTableId=route_table_id,
        DestinationCidrBlock=destination_cidr_block,
        TransitGatewayId=transit_gateway_id,
    )
    logger.info("Got response to add_route_tgw_nh {} ".format(resp))
    return resp

def delete_route(route_table_id, destination_cidr_block):
    """
    Deletes a route from the VPC route table
    :param route_table_id:
    :param destination_cidr_block:
    :return:
    """
    ec2 = boto3.client('ec2')
    resp = ec2.delete_route(
        DestinationCidrBlock=destination_cidr_block,
        RouteTableId=route_table_id,
    )
    logger.info("Got response to delete_route {} ".format(resp))
    return resp

def start_state_function(state_machine_arn):
    sfnConnection = boto3.client('stepfunctions')
    sfnConnection.start_execution(stateMachineArn=state_machine_arn)
    if sfnConnection.list_executions(stateMachineArn=state_machine_arn, statusFilter='RUNNING')[
        'executions']:
        logger.info("StateMachine is Running, hence exiting from execution")
    else:
        logger.info("StateMachine is not Running, hence starting StepFunction")
        sfnConnection.start_execution(stateMachineArn=state_machine_arn)



def lambda_handler(event, context):
    """
    Each VPC (including the security VPC) requires a static route directing traffic with a next hop of the
    TransitGatewayId.   In this case we take to route table id and  TransitGatewayId via environment variables from
    the CFT template.
    :param event:
    :param context:
    :return:
    """
    logger.info("Got event {} ".format(event))
    region = os.environ['region']
    toTGWRouteTable = os.environ['toTGWRouteTableId']
    VPC0_route_table_id = os.environ['vpc0HostRouteTableid']
    VPC1_route_table_id = os.environ['vpc1HostRouteTableid']
    transit_gateway_id = os.environ['transitGatewayid']
    init_fw_state_machine_arn = os.environ['InitFWStateMachine']

    responseData = {}
    responseData['data'] = 'Success'
    if event['RequestType'] == 'Create':
        resp = add_route_tgw_nh(VPC0_route_table_id, defroutecidr, transit_gateway_id)
        logger.info("Got response to route update on VPC0 {} ".format(resp))
        resp1 = add_route_tgw_nh(VPC1_route_table_id, defroutecidr, transit_gateway_id)
        logger.info("Got response to route update on VPC1 {} ".format(resp1))
        res2 = add_route_tgw_nh(toTGWRouteTable, vnetroutecidr, transit_gateway_id)
        logger.info("Got response to route update on SecVPC {} ".format(res2))

        start_resp = start_state_function(init_fw_state_machine_arn)
        logger.info("Calling start state function {} ".format(start_resp))
        cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        logger.info("Sending cfn success message ")

    elif event['RequestType'] == 'Update':
        print("Update something")

    elif event['RequestType'] == 'Delete':
        print("Got Delete event")
        try:
            res = delete_route(toTGWRouteTable, vnetroutecidr)
            res1 = delete_route(VPC0_route_table_id, defroutecidr)


        except Exception as e:
            print("Errory trying to delete something")
            cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")


if __name__=='__main__':
 if len(sys.argv)==2 and sys.argv[1]=='--help':
    print(__doc__)