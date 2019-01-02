# from commonLambdaFunctions import fetchFromTransitConfigTable, publishToSns, sendToQueue

import logging
import os

import boto3
import cfnresponse

logger = logging.getLogger()
logger.setLevel(logging.INFO)

defroutecidr = '0.0.0.0/0'
vnetroutecidr = '10.0.0.0/8'


def add_route(route_table_id, destination_cidr_block, transit_gateway_id):
    ec2 = boto3.client('ec2')

    resp = ec2.create_route(
        DryRun=False,
        RouteTableId=route_table_id,
        DestinationCidrBlock=destination_cidr_block,
        TransitGatewayId=transit_gateway_id,
    )
    logger.info("Got response to add_route {} ".format(resp))
    return resp


def delete_route(route_table_id, destination_cidr_block):
    ec2 = boto3.client('ec2')

    resp = ec2.delete_route(
        DestinationCidrBlock=destination_cidr_block,
        RouteTableId=route_table_id,
    )
    logger.info("Got response to delete_route {} ".format(resp))
    return resp


def lambda_handler(event, context):
    logger.info("Got event {} ".format(event))
    sec_route_table_id = os.environ['trustRouteTableid']
    VPC0_route_table_id = os.environ['vpc0HostRouteTableid']
    VPC1_route_table_id = os.environ['vpc1HostRouteTableid']
    transit_gateway_id = os.environ['transitGatewayid']

    responseData = {}
    responseData['data'] = 'Success'
    if event['RequestType'] == 'Create':
        resp = add_route(VPC0_route_table_id, defroutecidr, transit_gateway_id)
        logger.info("Got response to route update on VPC0 {} ".format(resp))
        resp1 = add_route(VPC1_route_table_id, defroutecidr, transit_gateway_id)
        logger.info("Got response to route update on VPC1 {} ".format(resp1))
        res2 = add_route(sec_route_table_id, vnetroutecidr, transit_gateway_id)
        logger.info("Got response to route update on SecVPC {} ".format(res2))
        result = cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
        logger.info("Got response to cfnsend {} ".format(result))

    elif event['RequestType'] == 'Update':
        print("Update something")

    elif event['RequestType'] == 'Delete':
        print("Got Delete event")
        try:
            res = delete_route(sec_route_table_id, vnetroutecidr)
            res1 = delete_route(VPC0_route_table_id, defroutecidr)
            result = cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")

        except Exception as e:
            print("Errory trying to delete something")
            cfnresponse.send(event, context, cfnresponse.SUCCESS, responseData, "CustomResourcePhysicalID")
