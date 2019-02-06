"""
Paloaltonetworks InitialiseFwLambda.py

Script triggered by a Lambda step function that will perform post initialisation tasks on the firewall config.

This software is provided without support, warranty, or guarantee.
Use at your own risk.
"""

import logging
import ssl
import urllib
import xml
import os
import netaddr
import xml.etree.ElementTree as et
import boto3


from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

lambda_client = boto3.client('lambda')
ec2_client = boto3.client('ec2')
gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

subnets = []


def find_subnet_by_id( subnet_id):
    """
    find a subnet by subnet ID. Sets a Filter based on the subnet_id and calls find_classic_subnet()
    :param subnet_id: 

    """
    kwargs = {
        'SubnetIds': [subnet_id]
    }
    return find_classic_subnet(kwargs)


def find_subnet_by_block(cidr):
    """find a subnet by CIDR block. Sets a Filter based on the subnet CIDR and calls find_classic_subnet()"""
    kwargs = {
        'Filters': [
            {
                'Name': 'cidrBlock',
                'Values': [cidr]
            }
        ]
    }
    return find_classic_subnet(kwargs)


def find_classic_subnet(kwargs):
    """call describe_subnets passing kwargs.  Returns the first subnet in the list of subnets.
    """
    logger.info("Querying for subnet")
    logger.debug("calling ec2.describe_subnets with args: %s", kwargs)
    try:
        subnets = ec2_client.describe_subnets(**kwargs)['Subnets']
    except ClientError:
        logger.debug("No Classic subnet found matching query.")
        return None
    logger.debug("Result: %s", subnets)
    if len(subnets) < 1:
        raise SystemExit("Error: 0 subnets found matching: %s" % kwargs)
    if len(subnets) > 1:
        raise SystemExit("Error: %s subnets found matching: %s" % (
            len(subnets), kwargs
        ))
    return subnets[0]


def updateRouteNexthop(route, hostname, api_key, subnetGateway, virtualRouter="default"):
    """
    Updates the firewall route table with the next hop of the default gateway in the AWS subnet

    :param hostname: IP address of the firewall
    :param api_key:
    :param subnetGateway: AWS subnet gateway (First IP in the subnet range)
    :param virtualRouter: VR where we wish to apply this route
    :return: Result of API request
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/" \
            "virtual-router/entry[@name='default']/routing-table/ip/static-route/entry[@name='vnets']"
    element = "<destination>{0}</destination><interface>ethernet1/2" \
              "</interface><nexthop><ip-address>{1}</ip-address></nexthop>".format(route, subnetGateway)


    return panSetConfig(hostname, api_key, xpath, element)


def panEditConfig(hostname, api_key, xpath, element):
    """
    Builds a request object and then Calls makeApiCall with request object.
    :param hostname: IP address of the firewall
    :param api_key:
    :param xpath: xpath of the configuration we wish to modify
    :param element: element that we wish to modify
    :return:  Returns the firewall response
    """
    logger.info("Updating edit config with xpath \n{} and element \n{} ".format(xpath, element))

    data = {
        'type': 'config',
        'action': 'edit',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = makeApiCall(hostname, data)

    return response


def makeApiCall(hostname, data):
    """
    Makes the API call to the firewall interface.  We turn off certificate checking before making the API call.
    Returns the API response from the firewall.
    :param hostname:
    :param data:
    :return: Expected response
    <response status="success">
        <result>
            <![CDATA[yes\n]]>
        </result>
    </response>
    """

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # No certificate check
    ctx.verify_mode = ssl.CERT_NONE
    url = "https://" + hostname + "/api"
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    return urllib.request.urlopen(url, data=encoded_data, context=ctx).read()


def panSetConfig(hostname, api_key, xpath, element):
    """Function to make API call to "set" a specific configuration
    """
    data = {
        'type': 'config',
        'action': 'set',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    logger.info("Updating set config with xpath \n{} and element \n{} ".format(xpath, element))
    response = makeApiCall(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response



def editIpObject(hostname, api_key, objectname, address):
    """Function to edit/update an existing IP Address object on a PA Node
    """
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{0}']/ip-netmask".format(
        objectname)
    element = "<ip-netmask>{0}</ip-netmask>".format(address)
    return panEditConfig(hostname, api_key, xpath, element)


def getApiKey(hostname, username, password):
    """Generate API keys using username/password
    API Call: http(s)://hostname/api/?type=keygen&user=username&password=password
    """
    data = {
        'type': 'keygen',
        'user': username,
        'password': password
    }
    response = makeApiCall(hostname, data)
    if response == 'error':
        logger.info("Got error making api call to get api key!")
        return response
    else:
        return xml.etree.ElementTree.XML(response)[0][0].text


def panCommit(hostname, api_key, message=""):
    """Function to commit configuration changes
    """
    data = {
        "type": "commit",
        "key": api_key,
        "cmd": "<commit>{0}</commit>".format(message)
    }
    return makeApiCall(hostname, data)


def get_gw_ip(cidr):
    ip = netaddr.IPNetwork(cidr)
    iplist = list(ip)
    return iplist[1]


def getFirewallStatus(gwMgmtIp, api_key):
    """
    Gets the firewall status by sending the API request show chassis status.
    :param gwMgmtIp:  IP Address of firewall interface to be probed
    :param api_key:  Panos API key
    """
    global gcontext

    cmd = urllib.request.Request("https://" + gwMgmtIp + "/api/?type=op&cmd=<show><chassis-ready></chassis-ready></show>&key=" + api_key)
    # Send command to fw and see if it times out or we get a response
    logger.info('[INFO]: Sending command: %s', cmd)
    try:
        response = urllib.request.urlopen(cmd, data=None, context=gcontext, timeout=5).read()
        #Now we do stuff to the gw
    except urllib.error.URLError:
        logger.info("[INFO]: No response from FW. So maybe not up!")
        return 'no'
        #sleep and check again?
    else:
        logger.info("[INFO]: FW is up!!")

    logger.info("[RESPONSE]: {}".format(response))
    resp_header = et.fromstring(response)

    if resp_header.tag != 'response':
        logger.info("[ERROR]: didn't get a valid response from firewall...maybe a timeout")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'error':
        logger.info("[ERROR]: Got an error for the command")
        return 'cmd_error'

    if resp_header.attrib['status'] == 'success':
        # The fw responded with a successful command execution. So is it ready?
        for element in resp_header:
            if element.text.rstrip() == 'yes':
                # Call config gw command?
                logger.info("[INFO]: FW is ready for configure")
                return 'yes'
            else:
                return 'almost'
            # The fw is still not ready to accept commands
            # so invoke lambda again and do this all over? Or just retry command?




def updateTGWFirewall(vpc_summary_route, fw_trust_ip, fw_untrust_ip, api_key, trustAZ_subnet_cidr, fw_untrust_int):
    """
    Parse the repsonse from makeApiCall()
    :param fw_trust_ip:
    :param fw_untrust_ip:
    :param api_key:
    :param trustAZ_subnet_cidr:
    :param fw_untrust_int:
    :return:
    If we see the string 'yes' in the repsonse we will assume that the firewall is up and continue with the firewall
    configuration
    """

    class FWNotUpException(Exception):
        pass
    err = 'no'
    while (True):
        err = getFirewallStatus(fw_trust_ip, api_key)
        if err == 'cmd_error':
            logger.info("[ERROR]: Command error from fw ")
            raise FWNotUpException('FW is not up!  Request Timeout')
            # terminate('false')
            # return
        elif err == 'no':
            # logger.info("[INFO] FW is not up...yet")
            # time.sleep(60)
            # continue
            raise FWNotUpException('FW is not up!')
        elif err == 'almost':
            # this means autocommit is happening
            # time.sleep(10)
            # continue
            raise FWNotUpException('FW is not up. Nic responds but DP not ready!')
        elif err == 'yes':
            logger.info("[INFO]: FW is up")
            break

    # Get the gateway IP for the trust subnet
    trustAZ_subnet_gw = get_gw_ip(trustAZ_subnet_cidr)

    # Update the route table with a static route
    updateRouteNexthop(vpc_summary_route,fw_trust_ip, api_key, trustAZ_subnet_gw, virtualRouter="default")

    # Update an address object of the firewall.
    editIpObject(fw_trust_ip, api_key, fw_untrust_int, fw_untrust_ip)



def lambda_handler(event, context):

    logger.info("Got Event {}".format(event))
    vpc_summary_route = os.environ['VpcSummaryRoute']
    fw1_trust_ip = os.environ['fw1TrustIp']
    fw2_trust_ip = os.environ['fw2TrustIp']
    fw1_untrust_ip = os.environ['fw1UntrustIp']
    fw2_untrust_ip = os.environ['fw2UntrustIp']
    trustAZ1_subnet = os.environ['trustAZ1Subnet']
    trustAZ2_subnet = os.environ['trustAZ2Subnet']
    api_key = os.environ['apikey']

    fw_untrust_int = 'Fw-Untrust-Int'

    trustAZ1_subnet_cidr = find_subnet_by_id(trustAZ1_subnet)['CidrBlock']
    logger.info('Trust AZ1 subnet is {}'.format(trustAZ1_subnet_cidr))
    trustAZ2_subnet_cidr = find_subnet_by_id(trustAZ2_subnet)['CidrBlock']
    logger.info('Trust AZ2 subnet is {}'.format(trustAZ2_subnet_cidr))

    updateTGWFirewall(vpc_summary_route,fw1_trust_ip, fw1_untrust_ip, api_key, trustAZ1_subnet_cidr, fw_untrust_int)
    panCommit(fw1_trust_ip, api_key, message="Updated route table and address object")
    updateTGWFirewall(vpc_summary_route,fw2_trust_ip, fw2_untrust_ip, api_key, trustAZ2_subnet_cidr, fw_untrust_int)
    panCommit(fw2_trust_ip, api_key, message="Updated route table and address object")
    logger.info("Failed to commit Firewall update")
    logger.info("Updated Firewalls")
