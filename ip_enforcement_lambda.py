"""
ip_enforcement_lambda.py
------------------------
Enforces IP reuse rules when EC2 instances launch or terminate.
Publishes change events to SNS and logs to S3.
"""

import os
import json
import boto3
from datetime import datetime, timezone, timedelta

# AWS Clients
dynamodb = boto3.resource('dynamodb')
ec2_client = boto3.client('ec2')
sns_client = boto3.client('sns')
s3_client = boto3.client('s3')

# Environment Variables (configured via Terraform)
TABLE_NAME = os.getenv('TABLE_NAME', 'IPSecurityControl')
SNS_TOPIC_ARN = os.getenv('SNS_TOPIC_ARN')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

def lambda_handler(event, context):
    """
    Main entry point for EC2 lifecycle events.
    - If TerminateInstances: mark IP as restricted.
    - If RunInstances: enforce restriction or allow, update table.
    """
    try:
        detail = event.get('detail', {})
        event_name = detail.get('eventName')
        user_identity = detail.get('userIdentity', {}).get('arn', 'UnknownUser')

        if event_name == "TerminateInstances":
            handle_termination_event(detail, user_identity)
        elif event_name == "RunInstances":
            handle_run_event(detail, user_identity)
        else:
            print(f"Unhandled eventName: {event_name}")

        return {"statusCode": 200, "message": "Event processed successfully."}
    except Exception as err:
        print(f"Error in lambda_handler: {err}")
        return {"statusCode": 500, "errorMessage": str(err)}

# ---------------------------------------------------------------------
# 1. TERMINATION LOGIC
# ---------------------------------------------------------------------

def handle_termination_event(detail, user_identity):
    """
    Marks the private IP as restricted for 3 years.
    """
    instances = detail.get('instancesSet', {}).get('items', [])

    table = dynamodb.Table(TABLE_NAME)
    now = datetime.now(timezone.utc)

    for instance in instances:
        private_ip = instance.get('privateIpAddress')
        instance_id = instance.get('instanceId')

        if not private_ip:
            print("No privateIpAddress found in termination event.")
            continue

        restricted_until = (now + timedelta(days=3 * 365)).strftime('%Y-%m-%d %H:%M:%S')

        # Fetch current record
        existing_record = table.get_item(Key={'PrivateIP': private_ip}).get('Item', None)
        old_state = existing_record if existing_record else {}

        # Update the record to restricted
        table.update_item(
            Key={'PrivateIP': private_ip},
            UpdateExpression=(
                "SET ResourceStatus = :restricted, "
                "restrictedUntilDate = :ru, "
                "LastUpdated = :lu"
            ),
            ExpressionAttributeValues={
                ":restricted": "restricted",
                ":ru": restricted_until,
                ":lu": now.strftime('%Y-%m-%d %H:%M:%S')
            }
        )

        print(f"Marked {private_ip} as restricted until {restricted_until}.")

        new_state = {
            "PrivateIP": private_ip,
            "ResourceStatus": "restricted",
            "restrictedUntilDate": restricted_until,
            "LastUpdated": now.strftime('%Y-%m-%d %H:%M:%S')
        }

        # Build a change event for SNS & S3
        change_event = {
            "ChangeType": "Update (Terminate)",
            "UserIdentity": user_identity,
            "Timestamp": now.isoformat(),
            "OldState": old_state,
            "NewState": new_state
        }
        # Notify
        send_sns_message(f"DynamoDB Change - {change_event['ChangeType']}", change_event)
        log_to_s3(change_event)


# ---------------------------------------------------------------------
# 2. LAUNCH LOGIC
# ---------------------------------------------------------------------

def handle_run_event(detail, user_identity):
    """
    Enforces IP restriction logic when an EC2 instance is launched.
    If restricted with mismatched tags, terminates the instance.
    Otherwise, updates DynamoDB (active status).
    """
    instances_set = detail.get('instancesSet', {}).get('items', [])
    response_set = detail.get('responseElements', {}).get('instancesSet', {}).get('items', [])

    if not instances_set or not response_set:
        raise ValueError("Missing instancesSet or responseElements in RunInstances event.")

    private_ip = instances_set[0].get('privateIpAddress')
    instance_id = response_set[0].get('instanceId')

    # Gather tags
    tags_list = instances_set[0].get('tags', [])
    tags_dict = {tag['Key']: tag['Value'] for tag in tags_list}

    print(f"RunInstances for {instance_id} - IP: {private_ip}, Tags: {tags_dict}")

    # Check restriction
    result = check_ip_restrictions(private_ip, tags_dict)
    if not result['allowed']:
        # Send restricted usage alert
        violation_details = {
            "Title": "Restricted IP Usage Detected",
            "PrivateIP": private_ip,
            "InstanceID": instance_id,
            "Issue": result['message'],
            "UserIdentity": user_identity,
            "Timestamp": datetime.now(timezone.utc).isoformat()
        }
        if "restriction_expiration" in result:
            violation_details["Availability"] = f"Restricted until {result['restriction_expiration']}"

        send_sns_message("Restricted IP Usage Detected", violation_details)
        print(f"Terminating {instance_id} due to IP restriction.")
        ec2_client.terminate_instances(InstanceIds=[instance_id])
        return

    # Otherwise, update the record as active
    update_dynamodb(private_ip, instance_id, tags_dict, user_identity)


def check_ip_restrictions(private_ip, tags):
    """
    Looks up the IP. If it's restricted & date not passed, ensures tags match for restoration.
    Returns {allowed: bool, message: str, restriction_expiration?: str}
    """
    table = dynamodb.Table(TABLE_NAME)
    record = table.get_item(Key={'PrivateIP': private_ip}).get('Item', None)

    now = datetime.now(timezone.utc)
    if record:
        restricted_until = record.get('restrictedUntilDate')
        if restricted_until:
            restricted_dt = datetime.strptime(restricted_until, '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
            if now < restricted_dt:
                # Check if tags match
                existing_tags = {
                    'AGT_HostName': record.get('AGT_HostName', 'UNKNOWN'),
                    'AGT_Application': record.get('AGT_Application', 'UNKNOWN'),
                    'AGT_AppFunc': record.get('AGT_AppFunc', 'UNKNOWN')
                }
                if (tags.get('AGT_HostName') == existing_tags['AGT_HostName']
                        and tags.get('AGT_Application') == existing_tags['AGT_Application']
                        and tags.get('AGT_AppFunc') == existing_tags['AGT_AppFunc']):
                    return {"allowed": True, "message": "Tags match; IP reuse allowed."}
                else:
                    return {
                        "allowed": False,
                        "message": f"PrivateIP {private_ip} is restricted until {restricted_dt}.",
                        "restriction_expiration": restricted_dt.strftime('%Y-%m-%d %H:%M:%S')
                    }

    # No record or restriction has expired => allowed
    return {"allowed": True, "message": "IP is not restricted or restriction has expired."}


def update_dynamodb(private_ip, resource_id, tags, user_identity):
    """
    Creates or updates the IP record, sets ResourceStatus=active, removes restrictedUntilDate.
    Publishes a change event to SNS & logs to S3.
    """
    table = dynamodb.Table(TABLE_NAME)
    now = datetime.now(timezone.utc)
    now_str = now.strftime('%Y-%m-%d %H:%M:%S')

    existing = table.get_item(Key={'PrivateIP': private_ip}).get('Item', None)
    change_event = {
        "UserIdentity": user_identity,
        "Timestamp": now.isoformat()
    }

    if existing:
        # Updating existing
        old_state = existing
        resource_id_history = existing.get('ResourceIDHistory', [])
        if resource_id not in resource_id_history:
            resource_id_history.append(resource_id)

        hostname_history = existing.get('HostNameHistory', [])
        new_hostname = tags.get('AGT_HostName', 'UNKNOWN')
        if new_hostname != 'UNKNOWN' and new_hostname not in hostname_history:
            hostname_history.append(new_hostname)

        new_state = dict(existing)
        new_state.update({
            "ResourceID": resource_id,
            "LastUpdated": now_str,
            "ResourceStatus": "active",
            "ResourceIDHistory": resource_id_history,
            "HostNameHistory": hostname_history,
            "AGT_HostName": new_hostname,
            "AGT_Application": tags.get('AGT_Application', 'UNKNOWN'),
            "AGT_AppFunc": tags.get('AGT_AppFunc', 'UNKNOWN')
        })

        table.update_item(
            Key={'PrivateIP': private_ip},
            UpdateExpression=(
                "SET ResourceID = :rid, "
                "LastUpdated = :lu, "
                "ResourceStatus = :status, "
                "ResourceIDHistory = :r_hist, "
                "HostNameHistory = :h_hist, "
                "AGT_HostName = :hn, "
                "AGT_Application = :app, "
                "AGT_AppFunc = :func "
                "REMOVE restrictedUntilDate"
            ),
            ExpressionAttributeValues={
                ":rid": resource_id,
                ":lu": now_str,
                ":status": "active",
                ":r_hist": resource_id_history,
                ":h_hist": hostname_history,
                ":hn": new_hostname,
                ":app": tags.get('AGT_Application', 'UNKNOWN'),
                ":func": tags.get('AGT_AppFunc', 'UNKNOWN')
            }
        )

        change_event["ChangeType"] = "Update (RunInstances)"
        change_event["OldState"] = old_state
        change_event["NewState"] = new_state
    else:
        # New IP
        new_hostname = tags.get('AGT_HostName', 'UNKNOWN')
        item = {
            "PrivateIP": private_ip,
            "ResourceID": resource_id,
            "ResourceStatus": "active",
            "LaunchDate": now_str,
            "LastUpdated": now_str,
            "ResourceIDHistory": [resource_id],
            "HostNameHistory": [new_hostname] if new_hostname != 'UNKNOWN' else [],
            "AGT_HostName": new_hostname,
            "AGT_Application": tags.get('AGT_Application', 'UNKNOWN'),
            "AGT_AppFunc": tags.get('AGT_AppFunc', 'UNKNOWN')
        }
        table.put_item(Item=item)

        change_event["ChangeType"] = "Add (RunInstances)"
        change_event["OldState"] = {}
        change_event["NewState"] = item

    send_sns_message(f"DynamoDB Change - {change_event['ChangeType']}", change_event)
    log_to_s3(change_event)
    print(f"Updated or created IP {private_ip} => {resource_id} now active.")


# ---------------------------------------------------------------------
# 3. NOTIFICATION & LOGGING
# ---------------------------------------------------------------------

def send_sns_message(subject, message_obj):
    """
    Publishes a message to SNS_TOPIC_ARN as JSON.
    """
    if not SNS_TOPIC_ARN:
        print("SNS_TOPIC_ARN not set. Skipping SNS publish.")
        return

    sns_client.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=json.dumps(message_obj, indent=2)
    )
    print(f"Sent SNS message: {subject}")


def log_to_s3(change_event):
    """
    Saves the change event to S3 for audit. 
    """
    if not S3_BUCKET_NAME:
        print("S3_BUCKET_NAME not set. Skipping S3 logging.")
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    private_ip = (
        change_event["NewState"].get("PrivateIP")
        or change_event["OldState"].get("PrivateIP", "UnknownIP")
    )
    object_key = f"ip_enforcement_changes/{timestamp}-{private_ip}.json"

    s3_client.put_object(
        Bucket=S3_BUCKET_NAME,
        Key=object_key,
        Body=json.dumps(change_event, indent=2),
        ContentType="application/json"
    )
    print(f"Logged event to s3://{S3_BUCKET_NAME}/{object_key}")
