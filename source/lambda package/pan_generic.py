#!/usr/bin/env python3

import ssl
import urllib
import xml
import boto3
import sys
import re





class XmlListConfig(list):
    def __init__(self, aList):
        for element in aList:
            if element:
                # treat like dict
                if len(element) == 1 or element[0].tag != element[1].tag:
                    self.append(XmlDictConfig(element))
                # treat like list
                elif element[0].tag == element[1].tag:
                    self.append(XmlListConfig(element))
            elif element.text:
                text = element.text.strip()
                if text:
                    self.append(text)

class XmlDictConfig(dict):
    '''
    Example usage:

    >>> tree = ElementTree.parse('your_file.xml')
    >>> root = tree.getroot()
    >>> xmldict = XmlDictConfig(root)

    Or, if you want to use an XML string:

    >>> root = ElementTree.XML(xml_string)
    >>> xmldict = XmlDictConfig(root)

    And then use xmldict for what it is... a dict.
    '''
    def __init__(self, parent_element):
        if parent_element.items():
            self.update(dict(parent_element.items()))
        for element in parent_element:
            if element:
                # treat like dict - we assume that if the first two tags
                # in a series are different, then they are all different.
                if len(element) == 1 or element[0].tag != element[1].tag:
                    aDict = XmlDictConfig(element)
                # treat like list - we assume that if the first two tags
                # in a series are the same, then the rest are the same.
                else:
                    # here, we put the list in dictionary; the key is the
                    # tag name the list elements all share in common, and
                    # the value is the list itself
                    aDict = {element[0].tag: XmlListConfig(element)}
                # if the tag has attributes, add those to the dict
                if element.items():
                    aDict.update(dict(element.items()))
                self.update({element.tag: aDict})
            # this assumes that if you've got an attribute in a tag,
            # you won't be having any text. This may or may not be a
            # good idea -- time will tell. It works for the way we are
            # currently doing XML configuration files...
            elif element.items():
                self.update({element.tag: dict(element.items())})
            # finally, if there are no child tags and no attributes, extract
            # the text
            else:
                self.update({element.tag: element.text})

def makeApiCall(hostname,data):
    '''Function to make API call
    '''
    # Todo: 
    # Context to separate function?
    # check response for status codes and return reponse.read() if success 
    #   Else throw exception and catch it in calling function
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    url = "https://" + hostname + "/api"
    encoded_data = urllib.parse.urlencode(data).encode('utf-8')
    return urllib.request.urlopen(url, data=encoded_data, context=ctx).read()

def getApiKey(hostname, username, password):
    '''Generate API keys using username/password
    API Call: http(s)://hostname/api/?type=keygen&user=username&password=password
    '''
    data = {
        'type' : 'keygen',
        'user' : username,
        'password' : password
    }
    response = makeApiCall(hostname, data)
    return xml.etree.ElementTree.XML(response)[0][0].text

def panOpCmd(hostname, api_key, cmd):
    '''Function to make an 'op' call to execute a command
    '''
    data = {
        "type" : "op",
        "key" : api_key,
        "cmd" : cmd
    }
    return makeApiCall(hostname, data)

def panCommit(hostname, api_key, message=""):
    '''Function to commit configuration changes
    '''
    data = {
        "type" : "commit",
        "key" : api_key,
        "cmd" : "<commit>{0}</commit>".format(message)
    }
    return makeApiCall(hostname, data)

def checkPaGroupReady(username, password, paGroup):
    '''Function to check whether a PaGroup (both Nodes N1 and N2) is ready to accept API calls
    This is done by trying to generate "API" key using username/password
    '''
    try:
        api_key_N1 = getApiKey(paGroup['N1Mgmt'], username, password)
        api_key_N2 = getApiKey(paGroup['N2Mgmt'], username, password)
        if api_key_N1 == api_key_N2:
            return True
        else:
            print("Error: API key of both nodes of the group doesn't match ")
            return False
    except:
        print("Error while retriving API Key")
        return False

# Test This
def configDeactivateLicenseApiKey(hostname, api_key, license_api_key):
    '''Function to configure DeactivateLicense API Key
    This function is used during initialization of a PA Node and requires internet connectivity
    '''
    cmd = "<request><license><api-key><set><key>" + license_api_key + "</key></set></api-key></license></request>"
    return panOpCmd(hostname, api_key, cmd)

# Test this
def deactivateLicense(hostname, api_key):
    '''Function to Deactivate / remove license associated with a PA node
    This function is used during decommision of a server and requires internet connectivity
    '''
    cmd = "<request><license><deactivate><VM-Capacity><mode>auto</mode></VM-Capacity></deactivate></license></request>"
    return panOpCmd(hostname, api_key, cmd)
    
def panSetConfig(hostname, api_key, xpath, element):
    '''Function to make API call to "set" a specific configuration
    '''
    data = {
        'type': 'config',
        'action': 'set',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = makeApiCall(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response

def panGetConfig(hostname, api_key, xpath):
    '''Function to make API call to "get" (or read or list) a specific configuration
    '''
    data = {
        'type': 'config',
        'action': 'get',
        'key': api_key,
        'xpath': xpath
    }
    response = makeApiCall(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response

def panEditConfig(hostname, api_key, xpath, element):
    '''Function to make API call to "edit" (or modify) a specific configuration
    Note: Some properties need "set" method instead of "edit" to work
    '''
    data = {
        'type': 'config',
        'action': 'edit',
        'key': api_key,
        'xpath': xpath,
        'element': element
    }
    response = makeApiCall(hostname, data)
    # process response and return success or failure?
    # Debug should print output as well?
    return response 


def panRollback(hostname, api_key, username="admin"):
    '''Function to rollback uncommited changes
    '''
    # https://firewall/api/?key=apikey&type=op&cmd=<revert><config><partial><admin><member>admin-name</member></admin></partial></config></revert>
    # panOpCmd(hostname, api_key, cmd)
    cmd = "<revert><config><partial><admin><member>" + username + "</member></admin></partial></config></revert>"
    panOpCmd(hostname, api_key, cmd)





def createIkeGateway(hostname, api_key, name, psk, ikeProfile, pa_dmz_inf, peerIp):
    '''Function to create IKE Gateway
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/ike/gateway/entry[@name='{0}']".format(name)
    element = "<authentication><pre-shared-key><key>{0}</key></pre-shared-key></authentication>\
              <protocol><ikev1><dpd><enable>yes</enable><interval>10</interval><retry>3</retry></dpd>\
              <ike-crypto-profile>{1}</ike-crypto-profile><exchange-mode>main</exchange-mode></ikev1>\
              <ikev2><dpd><enable>yes</enable></dpd></ikev2></protocol><protocol-common><nat-traversal>\
              <enable>no</enable></nat-traversal><fragmentation><enable>no</enable></fragmentation>\
              </protocol-common><local-address><interface>{2}</interface></local-address><peer-address>\
              <ip>{3}</ip></peer-address>".format(psk, ikeProfile, pa_dmz_inf, peerIp)
    # response from SecConfig is return so that incase needed, it can be used to do some processesing
    # In case of failure, Exception should be thrown by makeApiCall itself
    return panSetConfig(hostname, api_key, xpath, element)

def createIpecTunnelInf(hostname, api_key, tunnelInfId, tunnelInfIp="ip/30", mtu=1427):
    '''Function to create tunnel interface to use with IPsec
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/interface/tunnel/units/entry[@name='tunnel.{0}']".format(tunnelInfId)
    element = "<ip><entry name='{0}/30'/></ip><mtu>{1}</mtu>".format(tunnelInfIp, mtu)
    #print("Add: IpsecTunnelInf")
    #print(xpath)
    #print(element)
    return panSetConfig(hostname, api_key, xpath, element)

def createIpsecTunnel(hostname, api_key, tunnelName, ikeName, ipsecProfile, tunnelInfId):
    '''Function to create IPSec tunnel
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/tunnel/ipsec/entry[@name='{0}']".format(tunnelName)
    element = "<auto-key><ike-gateway><entry name='{0}'/></ike-gateway><ipsec-crypto-profile>{1}</ipsec-crypto-profile></auto-key><tunnel-monitor><enable>no</enable>\
              </tunnel-monitor><tunnel-interface>tunnel.{2}</tunnel-interface>".format(ikeName, ipsecProfile, tunnelInfId)
    print("Add: Ipsec Tunnel")
    print(xpath)
    print(element)
    return panSetConfig(hostname, api_key, xpath, element)

def isLicenseApplied():
    '''Function to check whether license is applied
    '''
    # Todo
    # return true if license is applied
    # return false if no license found
    pass

def isLicenseApiConfigured():
    '''Function to check whether deregister license api key is configured
    '''
    # Todo
    # Check whether license renewal mechanism is configured
    pass

def editIpObject(hostname, api_key, name, value):
    '''Function to edit/update an existing IP Address object on a PA Node
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address/entry[@name='{0}']/ip-netmask".format(name)
    element = "<ip-netmask>{0}</ip-netmask>".format(value)
    return panEditConfig(hostname, api_key, xpath, element)

def updateRouterIdAndAsn(hostname, api_key, routerId, routerAsn, virtualRouter="default"):
    '''Function to edit/update BGP RourterID(Public IP) and ASN on a PA Node
    /config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='default']/routing-table/ip/static-route/entry[@name='vnets']/destination
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='{0}']/protocol/bgp".format(virtualRouter)
    element = "<router-id>{0}</router-id><local-as>{1}</local-as>".format(routerId, routerAsn)
    return panSetConfig(hostname, api_key, xpath, element)

def updateDefaultRouteNextHope(hostname, api_key, subnetGateway, virtualRouter="default"):
    '''Function to update default route virtual router
    '''
    xpath = "/config/devices/entry[@name='localhost.localdomain']/network/virtual-router/entry[@name='{0}']/routing-table/ip/static-route/entry[@name='default']/nexthop".format(virtualRouter)
    element = "<ip-address>{0}</ip-address>".format(subnetGateway)
    return panSetConfig(hostname, api_key, xpath, element)

def pa_initialize(hostname, api_key, pa_dmz_priv_ip, pa_dmz_pub_ip, pa_asn, pa_dmz_subnet_gw, SubnetCidr, license_api_key=""):
    '''Function to initialize PA node
    '''
    # Update 'eth1' object with private IP of eth1 interface
    mask = SubnetCidr.split("/")[1]
    response1 = editIpObject(hostname, api_key, "eth1", "/".join([pa_dmz_priv_ip,mask]))
    # Update BGP router ID with public IP of eth1 and BGP ASN
    response2 = updateRouterIdAndAsn(hostname, api_key, pa_dmz_pub_ip, pa_asn)
    # Update next hop of static route to match subnet gw
    response3 = updateDefaultRouteNextHope(hostname, api_key, pa_dmz_subnet_gw)
    # Add ApiKey to deactivate License
    response4 = configDeactivateLicenseApiKey(hostname, api_key, license_api_key)
    return [response1, response2, response3, response4]



def panDelConfig(hostname, api_key, xpath):
    '''Function to delete delete a configuration
    '''
    data = {
            'type': 'config',
            'action': 'delete',
            'key': api_key,
            'xpath': xpath
            }
    response = makeApiCall(hostname, data)
    return response


