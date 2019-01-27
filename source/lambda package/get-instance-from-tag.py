# Read Environment Variables for Tags
# All TAGS should have a tag-name of 'tag_key_name'
# The primary firewall should have a tag-value of 'pri_fw_tag_key_value'
# The primary firewall should have a tag-value of 'sec_fw_tag_key_value'

# tag_key_name = os.environ['tag_key_name']
# prifw_tag_key_value = os.environ['prifw_tag_key_value']
# secfw_tag_key_value = os.environ['secfw_tag_key_value']
# int_index_number = os.environ['int_index_number']

def get_firewall_status_from_tags():

    tag_key_name = 'fw-ha-status'
    secfw_tag_key_value = 'def-route-primary'
    prifw_tag_key_value = 'inter-vpc-primary'
    int_index_number = 1


    logger.info('[INFO] Got event{}'.format(event))
    logger.info("tag_key_name: {}".format(tag_key_name))
    logger.info("prifw_tag_key_value: {}".format(prifw_tag_key_value))
    logger.info("secfw_tag_key_value: {}".format(secfw_tag_key_value))
    logger.info("Interface that pubip will be associated with is eth{}".format(int_index_number))

    # create filter for instances in running state
    filters = [
        {
            'Name': 'instance-state-name',
            'Values': ['running']
        }
    ]

    eiptagged = [
        {
            'Name': 'tag-key',
            'Values': [tag_key_name]

        }
    ]
    # filter the instances based on filters() above
    instances = ec2.instances.filter(Filters=eiptagged)

    VPNInstances = []
    logger.info("got these instances with the expected tags: {}".format(instances))

    for instance in instances:
        # for each instance, append to array
        ec2_instance = ec2.Instance(instance)
        VPNInstances.append(instance.id)
        logger.info("processing instance: {}".format(instance))
        for tag in instance.tags:
            if tag["Value"] == secfw_tag_key_value:
                secfw["instance"] = instance
                secfw["InterfaceId"] = instance.network_interfaces[2]
                logger.info("Found VPN secondaryfw instance.id via TAG value secondaryfw: {}".format(instance.id))
            elif tag["Value"] == prifw_tag_key_value:
                prifw["instance"] = instance
                prifw["InterfaceId"] = instance.network_interfaces[2]
                logger.info("Found VPN primaryfw instance.id via TAG value primaryfw: {}".format(instance.id))

    logger.info('[INFO] Primary firewall is {}'.format(prifw))
    logger.info('[INFO] Primary firewall is {}'.format(secfw))
    association = ec2.NetworkInterfaceAssociation('instance.id')
    return prifw, secfw
