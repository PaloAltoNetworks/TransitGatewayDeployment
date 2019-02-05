Help on module TransitGatewayRouteMonitorLambda:

NAME
    TransitGatewayRouteMonitorLambda - Palo Alto Networks TransitGatewayRouteMonitorLambda.py

FILE
    /Users/jharris/Documents/PycharmProjects/transitgateway/source/lambda package/TransitGatewayRouteMonitorLambda.py

DESCRIPTION
    Script triggered by a Cloudwatch event that will monitor the health of firewalls
    via the "show chassis status" op command on the Trust interface.
    The purpose is to assess the health of the firewall and modify an AWS route table to redirect
    traffic if the firewall is down.  When I firewall goes down routes within the route table bound to the
    TGW attachment will show next hop as blackhole.  The routes need to be updated to a functional eni.
    
    This software is provided without support, warranty, or guarantee.
    Use at your own risk.

FUNCTIONS
    check_for_split_routes(route_table_id, vpc_summary_route, def_route)
        Checks the route table if split_routes == True and if both the vpc_summary and Default point to the same eni
        Return False else Return True.  When split routes is True we want to use both firewalls.  Firewall 1 for internet
        traffic and firewall 2 for east/west traffic.
        
        :param route_table_id:  The route table that we will modify.
        :param vpc_summary_route:  A summary route used to forward all east west traffic to the alternative firewall if
        required
        :param def_route: The default route in this case 0.0.0.0/0
        :param route_table_id: route table the we need to check
        :return: True/False
    
    failover(route_table_id, failed_eni, backup_eni)
        Looks for routes that are blackholed by the failure of the firewall
        When it finds a route it will call replace_vpc_route_to_fw to update the next hop to a functional eni
        
        :param route_table_id: The route table that requires modification
        :param failed_eni: NetworkInterfaceId: The eni of the Firewall that has failed
        :param backup_eni: NetworkInterfaceId: The eni of the Firewall that we need to failover to
        :return:
    
    get_firewall_status(gwMgmtIp, api_key)
        Reruns the status of the firewall.  Calls the op command show chassis status
        Requires an apikey and the IP address of the interface we send the api request
        :param gwMgmtIp:
        :param api_key:
        :return:
    
    lambda_handler(event, context)
        Controls the failover of routing of traffic between VPC's and to the internet.   In the event of a failure the
        backup firewall will provide routing and security
        
        
        preempt = os.environ['preempt'] Set this value to TRUE if you wish the firewalls to return to an Active/Active state
        as soon as the failed firewall becomees healthy again or set it to true in the environment variables during a change
        window.
        vpc_summary_route = os.environ['VpcSummaryRoute'] Set thus value as a route that summarises wth VPC spokes. The
        security VPC should not be contained in this summary route.
        fw1_trust_eni = os.environ['fw1Trusteni']  Fw 1 trust eni id
        fw2_trust_eni = os.environ['fw2Trusteni']  Fw 1 trust eni id
        route_table_id = os.environ['fromTGWRouteTableId']  Route table id of the route table associated with the TGW attachment
        fw1_trust_ip = os.environ['fw1Trustip'] FW Trust Inteface IP used for health probies.
        fw2_trust_ip = os.environ['fw2Trustip'] FW Trust Inteface IP used for health probies.
        api_key = os.environ['apikey']
        split_routes = os.environ['splitroutes'] Select True if you intend to use both firewalls One for east/West and
        one for internet.
        :param event:
        :param context:
        :return:
    
    replace_vpc_route_to_fw(route_table_id, destination_cidr_block, NetworkInterfaceId, DryRun=False)
        Scan the route table for blackhole routes where the next hop is the eni of the failed firewall.
        In order to replace the routes we first delete the route and then add a new route pointing to the
        backup eni.
        
        :param route_table_id: The route table that requires modification
        :param destination_cidr_block: The cidr block that we need to change.  Normally the default route and VPC summary route
        :param NetworkInterfaceId: The eni of the Firewall that we need to failover to
        :param DryRun: Perform a DryRun - Doesn't update the route table
        :return: Respone to route_create or 'None'

DATA
    client = <botocore.client.EC2 object>
    context = {}
    ec2 = ec2.ServiceResource()
    ec2_client = <botocore.client.EC2 object>
    event = {}
    events_client = <botocore.client.CloudWatchEvents object>
    gcontext = <ssl.SSLContext object>
    logger = <logging.RootLogger object>
    prifw = {}
    secfw = {}


