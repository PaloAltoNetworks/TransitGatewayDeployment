"""
Palo Alto Networks TransitGatewayInitialiseLambda.py

Script triggered by a Cloudformation that will create route table entries in each VPC that use next hop of the
transit gateway attachment.  We use this script today as next hop TransitGatewayId is not supported in CFT yet
When CFT use the updated boto3 libraries we can remove this function and place the route entries using CFT.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
"""
import logging
import os
import boto3
import cfnresponse


logger = logging.getLogger()
logger.setLevel(logging.INFO)

defroutecidr = '0.0.0.0/0'
vnetroutecidr = '10.0.0.0/8'


def add_route_tgw_nh(route_table_id, destination_cidr_block, transit_gateway_id):
    '''
    Adds a route to a VPC route table with next hop of the TransitGatewayId
    :param route_table_id:
    :param destination_cidr_block:
    :param transit_gateway_id:
    :return:
    '''
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
    '''
    Deletes a route from the VPC route table
    :param route_table_id:
    :param destination_cidr_block:
    :return:
    '''
    ec2 = boto3.client('ec2')
    resp = ec2.delete_route(
        DestinationCidrBlock=destination_cidr_block,
        RouteTableId=route_table_id,
    )
    logger.info("Got response to delete_route {} ".format(resp))
    return resp


def lambda_handler(event, context):
    '''
    Each VPC (including the security VPC) requires a static route directing traffic with a next hop of the
    TransitGatewayId.   In this case we take to route table id and  TransitGatewayId via environment variables from
    the CFT template.
    :param event:
    :param context:
    :return:
    '''
    logger.info("Got event {} ".format(event))
    region = os.environ['region']
    toTGWRouteTable = os.environ['toTGWRouteTableId']
    VPC0_route_table_id = os.environ['vpc0HostRouteTableid']
    VPC1_route_table_id = os.environ['vpc1HostRouteTableid']
    transit_gateway_id = os.environ['transitGatewayid']

    responseData = {}
    responseData['data'] = 'Success'
    if event['RequestType'] == 'Create':
        resp = add_route_tgw_nh(VPC0_route_table_id, defroutecidr, transit_gateway_id)
        logger.info("Got response to route update on VPC0 {} ".format(resp))
        resp1 = add_route_tgw_nh(VPC1_route_table_id, defroutecidr, transit_gateway_id)
        logger.info("Got response to route update on VPC1 {} ".format(resp1))
        res2 = add_route_tgw_nh(toTGWRouteTable, vnetroutecidr, transit_gateway_id)
        logger.info("Got response to route update on SecVPC {} ".format(res2))
        result = cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        logger.info("Got response to cfnsend {} ".format(result))

    elif event['RequestType'] == 'Update':
        print("Update something")

    elif event['RequestType'] == 'Delete':
        print("Got Delete event")
        try:
            res = delete_route(toTGWRouteTable, vnetroutecidr)
            res1 = delete_route(VPC0_route_table_id, defroutecidr)
            result = cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")

        except Exception as e:
            print("Errory trying to delete something")
            cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
