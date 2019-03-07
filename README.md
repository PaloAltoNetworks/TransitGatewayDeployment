# AWS Transit Gateway
Creates a Transit Gateway with two server VPCs and a security VPC

Prerequisites
1) Create an S3 bucket for the lambda.zip files
2) Create an S3 bucket for the bootstrap files

The firewall management interface can be reached via the NAT instance

The default account for the firewalls is

panadmin/Pal0Alt0123!


# AWS Transit VPC with VM-Series

This solution deploys a secured Transit Gateway in AWS.  This allows you to secure many spoke or VPCs using centralized VM-Series firewalls in the Security VPC.   This solution will secure traffic between VPCs, between a VPC and an on-prem/hybrid cloud resource, and outbound traffic.  Securing outbound traffic in the Security VPC allows you to allow safely enabled access to the Internet for tasks like software installs and patches without backhauling the traffic to an on prem-firewall for security.

AWS Transit Gateway is a service that enables customers to connect their Amazon Virtual Private Clouds (VPCs) and their on-premises networks to a single gateway. As you grow the number of workloads running on AWS, you need to be able to scale your networks across multiple accounts and Amazon VPCs to keep up with the growth. Today, you can connect pairs of Amazon VPCs using peering. However, managing point-to-point connectivity across many Amazon VPCs, without the ability to centrally manage the connectivity policies, can be operationally costly and cumbersome. For on-premises connectivity, you need to attach your AWS VPN to each individual Amazon VPC. This solution can be time consuming to build and hard to manage when the number of VPCs grows into the hundreds.

With AWS Transit Gateway, you only have to create and manage a single connection from the central gateway in to each Amazon VPC, on-premises data center, or remote office across your network. Transit Gateway acts as a hub that controls how traffic is routed among all the connected networks which act like spokes. This hub and spoke model significantly simplifies management and reduces operational costs because each network only has to connect to the Transit Gateway and not to every other network. Any new VPC is simply connected to the Transit Gateway and is then automatically available to every other network that is connected to the Transit Gateway. This ease of connectivity makes it easy to scale your network as you grow.


The deployment guide can be found here [Transit Gatway with VM-Series Deployment Guide](https://github.com/PaloAltoNetworks/TransitGatewayDeployment/blob/master/Documentation/AWS_Transit_Gateway_ManualBuild.pdf?raw=true)

![alt_text](https://github.com/PaloAltoNetworks/TransitGatewayDeployment/blob/master/Documentation/images/TransitGateway.png "topology")

# Support Policy: Community-Supported
The code and templates in this repository are released under an as-is, best effort, support policy. These scripts should viewed as community supported and Palo Alto Networks will contribute our expertise as and when possible. We do not provide technical support or help in using or troubleshooting the components of the project through our normal support options such as Palo Alto Networks support teams, or ASC (Authorized Support Centers) partners and backline support options. The underlying product used (the VM-Series firewall) by the scripts or templates are still supported, but the support is only for the product functionality and not for help in deploying or using the template or script itself. Unless explicitly tagged, all projects or work posted in our GitHub repository (at https://github.com/PaloAltoNetworks) or sites other than our official Downloads page on https://support.paloaltonetworks.com are provided under the best effort policy.

