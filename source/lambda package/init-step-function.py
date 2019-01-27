from __future__ import print_function

import json
import boto3

print('Loading function')
batch = boto3.client('batch')
def lambda_handler(event, context):
    # Log the received event
    print("Received event: " + json.dumps(event, indent=2))
    # Get parameters for the SubmitJob call
    # http://docs.aws.amazon.com/batch/latest/APIReference/API_SubmitJob.html
    jobName = event['jobName']
    jobQueue = event['jobQueue']
    jobDefinition = event['jobDefinition']
    # containerOverrides and parameters are optional
    if event.get('containerOverrides'):
        containerOverrides = event['containerOverrides']
    else:
        containerOverrides = {}
    if event.get('parameters'):
        parameters = event['parameters']
    else:
        parameters = {}

    try:
        # Submit a Batch Job
        response = batch.submit_job(jobQueue=jobQueue, jobName=jobName, jobDefinition=jobDefinition,
                                    containerOverrides=containerOverrides, parameters=parameters)
        # Log response from AWS Batch
        print("Response: " + json.dumps(response, indent=2))
        # Return the jobId