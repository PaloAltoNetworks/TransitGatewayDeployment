# Help on module TransitGatewayInitialiseLambda:

# NAME

    TransitGatewayInitialiseLambda - Paloaltonetworks TransitGatewayInitialiseLambda.py

# FILE

    TransitGatewayInitialiseLambda.py

# DESCRIPTION

    Script triggered from a custom resource.  The script performs two funcitons
    
    1) The script will create route table entries in each VPC that use next hop of the
    transit gateway attachment.  We use this script today as next hop TransitGatewayId is not supported in CFT yet
    When CFT use the updated boto3 libraries we can remove this function and place the route entries using CFT.
    
    1) The script will start a step function that will complete the configuration of the Paloaltonetworks firewalls
    Two post deployment tasks are performed by the InitialiseFwlambda.py script associated with the step function
    
    This software is provided without support, warranty, or guarantee.
    Use at your own risk.

# FUNCTIONS
    
##     add_route_tgw_nh(route_table_id, destination_cidr_block, transit_gateway_id)

        Adds a route to a VPC route table with next hop of the TransitGatewayId
        :param route_table_id:
        :param destination_cidr_block:
        :param transit_gateway_id:
        :return:
    
##     delete_route(route_table_id, destination_cidr_block)

        Deletes a route from the VPC route table
        :param route_table_id:
        :param destination_cidr_block:
        :return:
    
##     lambda_handler(event, context)

        Each VPC (including the security VPC) requires a static route directing traffic with a next hop of the
        TransitGatewayId.   In this case we take to route table id and  TransitGatewayId via environment variables from
        the CFT template.
        :param event:
        :param context:
        :return:
    
##     start_state_function(state_machine_arn)

DATA
    defroutecidr = '0.0.0.0/0'
    logger = <logging.RootLogger object>
    vnetroutecidr = '10.0.0.0/8'


