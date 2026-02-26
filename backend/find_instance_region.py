"""
Find which region the instance is actually in
"""
import boto3

# Assume role
sts = boto3.client('sts', region_name='us-east-1')
response = sts.assume_role(
    RoleArn='arn:aws:iam::482995014361:role/ReadOnly-Cross-Account',
    RoleSessionName='find-instance',
    DurationSeconds=3600
)

creds = response['Credentials']
session = boto3.Session(
    aws_access_key_id=creds['AccessKeyId'],
    aws_secret_access_key=creds['SecretAccessKey'],
    aws_session_token=creds['SessionToken']
)

instance_id = 'i-0d829e3c55c3fb2a2'

# Get all regions
ec2_client = session.client('ec2', region_name='us-east-1')
regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]

print(f"Searching for instance {instance_id} across {len(regions)} regions...")
print("=" * 60)

for region in regions:
    try:
        ec2 = session.client('ec2', region_name=region)
        response = ec2.describe_instances(InstanceIds=[instance_id])
        
        if response['Reservations']:
            instance = response['Reservations'][0]['Instances'][0]
            print(f"\nFOUND in region: {region}")
            print(f"  State: {instance['State']['Name']}")
            print(f"  Monitoring: {instance.get('Monitoring', {}).get('State', 'unknown')}")
            print(f"  Instance Type: {instance.get('InstanceType', 'unknown')}")
            print(f"  Launch Time: {instance.get('LaunchTime', 'unknown')}")
            
            # Check CloudWatch metrics
            cw = session.client('cloudwatch', region_name=region)
            metrics = cw.list_metrics(
                Namespace='AWS/EC2',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}]
            )
            metric_names = [m['MetricName'] for m in metrics.get('Metrics', [])]
            print(f"  Available metrics: {metric_names}")
            break
    except:
        pass  # Instance not in this region

print("\n" + "=" * 60)
