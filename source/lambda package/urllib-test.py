import urllib.request as req
import urllib.parse
import ssl
import xml

from __future__ import print_function

import json
import boto3

print('Loading function')

batch = boto3.client('batch')




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

def lambda_handler(event, context):
    # Log the received event
    print("Received event: " + json.dumps(event, indent=2))
    # Get jobId from the event
    jobId = event['jobId']

    try:
        # Call DescribeJobs
        response = batch.describe_jobs(jobs=[jobId])
        # Log response from AWS Batch
        print("Response: " + json.dumps(response, indent=2))
        # Return the jobtatus
        jobStatus = response['jobs'][0]['status']
        return jobStatus
    except Exception as e:
        print(e)
        message = 'Error getting Batch Job status'
        print(message)
        raise Exception(message)