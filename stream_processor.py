"""
stream_processor.py
-------------------
Listens to the DynamoDB Streams of the IPSecurityControl table.
Sends an alert (SNS) whenever any record is added/updated/deleted,
so we catch manual or out-of-band changes.
"""

import os
import json
import boto3
from datetime import datetime, timezone

sns_client = boto3.client('sns')
s3_client = boto3.client('s3')

SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')     # Same single SNS topic
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')   # Same or different S3 bucket

def lambda_handler(event, context):
    """
    Processes a batch of DynamoDB Stream records.
    Each record might be an INSERT, MODIFY, or REMOVE.
    """
    for record in event.get('Records', []):
        event_name = record.get('eventName')  # e.g. "INSERT", "MODIFY", "REMOVE"
        ddb_data = record.get('dynamodb', {})
        old_image = ddb_data.get('OldImage', {})
        new_image = ddb_data.get('NewImage', {})

        old_state = convert_ddb_image_to_dict(old_image)
        new_state = convert_ddb_image_to_dict(new_image)

        change_event = {
            "ChangeType": event_name,
            "Timestamp": datetime.now(timezone.utc).isoformat(),
            "OldState": old_state,
            "NewState": new_state
        }

        # Send a generic SNS message
        send_sns_message(f"DynamoDB Stream Change - {event_name}", change_event)

        # (Optional) log to S3 for audit
        log_to_s3(change_event)


def convert_ddb_image_to_dict(ddb_image):
    """
    Convert DynamoDB Stream 'image' to a normal Python dict
    """
    from boto3.dynamodb.types import TypeDeserializer
    deserializer = TypeDeserializer()

    result = {}
    for k, v in ddb_image.items():
        result[k] = deserializer.deserialize(v)
    return result


def send_sns_message(subject, message_obj):
    """
    Publish the change event to the same single SNS topic.
    """
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not set, skipping SNS publish.")
        return

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=json.dumps(message_obj, indent=2)
    )
    print(f"Stream Processor: Sent SNS message => {subject}")


def log_to_s3(change_event):
    """
    Store the stream change event in S3 for auditing.
    """
    if not S3_BUCKET_NAME:
        print("S3_BUCKET_NAME not set, skipping S3 logging.")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    # Attempt to find PrivateIP in new or old
    private_ip = new_or_old_private_ip(change_event)

    object_key = f"dynamodb-stream-changes/{timestamp}-{private_ip}.json"

    s3_client.put_object(
        Bucket=S3_BUCKET_NAME,
        Key=object_key,
        Body=json.dumps(change_event, indent=2),
        ContentType="application/json"
    )
    print(f"Stream Processor: Logged event to s3://{S3_BUCKET_NAME}/{object_key}")


def new_or_old_private_ip(change_event):
    return (
        change_event["NewState"].get("PrivateIP")
        or change_event["OldState"].get("PrivateIP", "UnknownIP")
    )
