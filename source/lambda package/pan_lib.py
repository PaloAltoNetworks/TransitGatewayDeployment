from pandevice import firewall
from pandevice import policies
from pandevice import objects
import logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

import os

class PAN_FW:

    def __init__(self, fw_ip, u_name, paswd,
                 untrust_zone, trust_zone, security_rule_name,
                 rule_action, dag_name, dag_tag_name, 
                 ):
        self.fw_ip = fw_ip
        self.u_name = u_name
        self.paswd = paswd 
        self.rulebase = None
        self.untrust_zone = untrust_zone
        self.trust_zone = trust_zone 
        self.security_rule_name = security_rule_name
        self.rule_action = rule_action
        self.dag_name = dag_name
        self.dag_tag_name = dag_tag_name
        self.fw_hndl = None 

    def init_fw_handle(self):
        """
        Initialize a handle to the firewall
        """
        self.fw_hndl = firewall.Firewall(self.fw_ip, self.u_name, self.paswd)
        print self.fw_hndl.refresh_system_info()

    def cache_rulebase(self):
        """
        Method to cache a handle to the rulebase 
        """
        rulebase = policies.Rulebase()
        self.fw_hndl.add(rulebase)
        print policies.SecurityRule.refreshall(rulebase)
        self.rulebase = rulebase

    def update_address_object(self, addr_object):
        try:
            ret = objects.AddressObject.update(self, addr_object)
        except:
            logger.info("[INFO]: No response from FW. So maybe not up!")
            return 'error'




    def check_security_rules(self):
        
        current_security_rules = policies.SecurityRule.refreshall(self.rulebase)

        print('Current security rules: {}'.format(len(current_security_rules)))
        for rule in current_security_rules:
            print('- {}'.format(rule.name))
        
        if self.security_rule_name in current_security_rules:
            return True
        else:
            return False

    def check_dag_exists(self, dag_name):
        """
        Introspect the VM-Series FW and check if the 
        DAG exists
        :param device: 
        :param group_name: 
        :return: 
        """
        dag_list, _ = self.get_all_address_group()
        if dag_name in dag_list:
            return True 
        else:
            return False

    def get_all_address_group(self):
        """
        Retrieve all the tag to IP address mappings
        :param device:
        :return:
        """
        try:
            ret = objects.AddressGroup.refreshall(self.fw_hndl)
        except:
            logger.info("[INFO]: No response from FW. So maybe not up!")
            return 'error'

        if exc:
            return (False, exc)
        else:
            l = []
            for item in ret:
                l.append(item.name)
            return l, exc

    def add_address_group(self, ag_object):
        """
        Create a new dynamic address group object on the
        PAN FW.
        """

        self.fw_hndl.add(ag_object)
        ag_object.create()
        return True

    @staticmethod
    def create_address_group_object(**kwargs):
        """
        Create an Address object
        @return False or ```objects.AddressObject```
        """
        ad_object = objects.AddressGroup(
            name=kwargs['address_gp_name'],
            dynamic_value=kwargs['dynamic_value'],
            description=kwargs['description'],
            tag=kwargs['tag_name']
        )
        if ad_object.static_value or ad_object.dynamic_value:
            return ad_object
        else:
            return None

    def register_ip_to_tag_map(self, ip_addresses):
        """
        :param device:
        :param ip_addresses:
        :param tag:
        :return:
        """

        exc = None
        try:
            self.fw_hndl.userid.register(ip_addresses, self.dag_tag_name)
        except Exception, e:
                exc = get_exception()

        if exc:
            return (False, exc)
        else:
            return (True, exc)

    @staticmethod
    def create_security_rule(**kwargs):
        """
         Create a security rule object and return 
         the object handle
        """
        security_rule = policies.SecurityRule(
            name=kwargs['rule_name'],
            description=kwargs['description'],
            fromzone=kwargs['source_zone'],
            #source=kwargs['source_ip'],
            source_user=kwargs['source_user'],
            hip_profiles=kwargs['hip_profiles'],
            tozone=kwargs['destination_zone'],
            destination=kwargs['destination_ip'],
            application=kwargs['application'],
            service=kwargs['service'],
            category=kwargs['category'],
            log_start=kwargs['log_start'],
            log_end=kwargs['log_end'],
            action=kwargs['action'],
            type=kwargs['rule_type']
        )

        if 'tag_name' in kwargs:
            security_rule.tag = kwargs['tag_name']

        # profile settings
        if 'group_profile' in kwargs:
            security_rule.group = kwargs['group_profile']
        else:
            if 'antivirus' in kwargs:
                security_rule.virus = kwargs['antivirus']
            if 'vulnerability' in kwargs:
                security_rule.vulnerability = kwargs['vulnerability']
            if 'spyware' in kwargs:
                security_rule.spyware = kwargs['spyware']
            if 'url_filtering' in kwargs:
                security_rule.url_filtering = kwargs['url_filtering']
            if 'file_blocking' in kwargs:
                security_rule.file_blocking = kwargs['file_blocking']
            if 'data_filtering' in kwargs:
                security_rule.data_filtering = kwargs['data_filtering']
            if 'wildfire_analysis' in kwargs:
                security_rule.wildfire_analysis = kwargs['wildfire_analysis']
        return security_rule

    def insert_rule(self, sec_rule):
        """
        Insert the policy for AWS Security Hub
        at the top of the ruleset. 
        """
        print("Inserting Rule into the top spot.")
        self.rulebase.insert(0, sec_rule)
        sec_rule.apply_similar()
        #rulebase.apply()

    def commit(self):
        """
         Commit settings on the firewall. 
        """ 
        try:
            self.fw_hndl.commit(sync=True)
        except:
            logger.info("[INFO]: No response from FW. So maybe not up!")
            return 'error'

def handle_gd_threat_intel(event, context):

    l_event = None
    ip_list = []
    print("Received event: " + json.dumps(event, indent=2))
    print("Event type: {}".format(type(event)))
    if isinstance(event, (list, tuple)):
        print("There are potentially multiple events")
        for _event in event:
            print("********** Dict: Event details: {}".format(_event))
            ip = process_threat_intel_data(_event)
            ip_list.append(ip)
        return ip_list
    else:
        print("There is only a single event to process in this finding. ")
        l_event = event
        print("Dict: Event details: {}".format(event))
        ip_address = process_threat_intel_data(l_event)
        return ip_address

def local_handle_gd_threat_intel(event):

    l_event = None
    ip_list = []
    print("Received event: " + json.dumps(event, indent=2))
    print("Event type: {}".format(type(event)))
    if isinstance(event, (list, tuple)):
        #l_event = event[0]
        #print("Extracted time from list: {}".format(l_event))
        print("There are potentially multiple events")
        for _event in event:
            print("*********** Dict: Event details: {}".format(_event))
            ip = process_threat_intel_data(_event)
            ip_list.append(ip)
        return ip_list
    else:
        l_event = event
        print("Dict: Event details: {}".format(event))
        process_threat_intel_data(l_event)

def process_threat_intel_data(event):
    """
    Process the threat finding to 
    take the appropriate action.
    
    :param event: 
    :return: 
    """

    print("GuardDuty Finding Event Details: {}".format(event))
    detail = event.get('detail')
    service = detail.get('service')
    print("Service details: {}".format(service))
    action = service.get('action')
    print("Action: {}".format(action))

    # Now need to demultiplex the action key-value pairs
    actionType = action.get('actionType')

    ip_address = None
    if actionType == "PORT_PROBE":
        ip_address = handle_port_probe_action(action)
    elif actionType == "AWS_API_CALL":
        ip_address = handle_aws_api_call_action(action)
    elif actionType == "DNS_REQUEST":
        print("DNS Request received. NO OP.")
    elif actionType == "NETWORK_CONNECTION":
        print("Not yet handling this.")

    return ip_address

def handle_gd_network_connection_action(data):
    """
    Process the NETWORK_CONNECTION action type
    from the guard duty finding.
    
    :param data: 
    :return: 
    """
    pass

def handle_aws_api_call_action(action):
    """
    Process the AWS_API_CALL action type from 
    the guard duty finding.
    
    :param data: 
    :return: 
    """
    apiCallAction = action.get("awsApiCallAction")
    print("apiCallAction: {}".format(apiCallAction))
    remoteIpDetails = apiCallAction.get("remoteIpDetails")
    print("remoteIpDetails: {}".format(remoteIpDetails))
    ipAddressV4 = remoteIpDetails.get('ipAddressV4')
    print("Guard Duty Flagged IP: {}".format(ipAddressV4))
    return ipAddressV4

def handle_port_probe_action(action):
    """
    Handle the PORT_PROBE action type from the 
    guard duty finding.
    :param data: 
    :return: 
    """
    portProbeAction = action.get("portProbeAction")
    print("Port Probe action: {}".format(portProbeAction))
    portProbeDetails = portProbeAction.get("portProbeDetails")
    remoteIpDetails = portProbeDetails[0].get("remoteIpDetails")
    ip_address = remoteIpDetails.get("ipAddressV4")
    print("Port probe Address originated from {}".format(ip_address))
    return ip_address








