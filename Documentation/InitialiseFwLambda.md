Help on module InitialiseFwLambda:

NAME
    InitialiseFwLambda - Paloaltonetworks InitialiseFwLambda.py

FILE
    /Users/jharris/Documents/PycharmProjects/transitgateway/source/lambda package/InitialiseFwLambda.py

DESCRIPTION
    Script triggered by a Lambda step function that will perform post initialisation tasks on the firewall config.
    
    This software is provided without support, warranty, or guarantee.
    Use at your own risk.

FUNCTIONS
    editIpObject(hostname, api_key, name, value)
        Function to edit/update an existing IP Address object on a PA Node
    
    find_classic_subnet(kwargs)
        call describe_subnets passing kwargs.  Returns the first subnet in the list of subnets.
    
    find_subnet_by_block(cidr)
        find a subnet by CIDR block. Sets a Filter based on the subnet CIDR and calls find_classic_subnet()
    
    find_subnet_by_id(subnet_id)
        find a subnet by subnet ID. Sets a Filter based on the subnet_id and calls find_classic_subnet()
        :param subnet_id:
    
    getApiKey(hostname, username, password)
        Generate API keys using username/password
        API Call: http(s)://hostname/api/?type=keygen&user=username&password=password
    
    getFirewallStatus(gwMgmtIp, api_key)
        Gets the firewall status by sending the API request show chassis status.
        :param gwMgmtIp:  IP Address of firewall interface to be probed
        :param api_key:  Panos API key
    
    get_gw_ip(cidr)
    
    lambda_handler(event, context)
    
    makeApiCall(hostname, data)
            Makes the API call to the firewall interface.  We turn off certificate checking before making the API call.
            Returns the API response from the firewall.
            :param hostname:
            :param data:
            :return: Expected response
            <response status="success">
                <result>
                    <![CDATA[yes
        ]]>
                </result>
            </response>
    
    panCommit(hostname, api_key, message='')
        Function to commit configuration changes
    
    panEditConfig(hostname, api_key, xpath, element)
        Builds a request object and then Calls makeApiCall with request object.
        :param hostname: IP address of the firewall
        :param api_key:
        :param xpath: xpath of the configuration we wish to modify
        :param element: element that we wish to modify
        :return:  Returns the firewall response
    
    panSetConfig(hostname, api_key, xpath, element)
        Function to make API call to "set" a specific configuration
    
    updateRouteNexthop(hostname, api_key, subnetGateway, virtualRouter='default')
        Updates the firewall route table with the next hop of the default gateway in the AWS subnet
        
        :param hostname: IP address of the firewall
        :param api_key:
        :param subnetGateway: AWS subnet gateway (First IP in the subnet range)
        :param virtualRouter: VR where we wish to apply this route
        :return: Result of API request
    
    updateTGWFirewall(fw_trust_ip, fw_untrust_ip, api_key, trustAZ_subnet_cidr, fw_untrust_int)
        Parse the repsonse from makeApiCall()
        :param fw_trust_ip:
        :param fw_untrust_ip:
        :param api_key:
        :param trustAZ_subnet_cidr:
        :param fw_untrust_int:
        :return:
        If we see the string 'yes' in the repsonse we will assume that the firewall is up and continue with the firewall
        configuration

DATA
    ec2_client = <botocore.client.EC2 object>
    gcontext = <ssl.SSLContext object>
    lambda_client = <botocore.client.Lambda object>
    logger = <logging.RootLogger object>
    subnets = []


