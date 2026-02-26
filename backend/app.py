import os
import json
import time
import logging
import uuid
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from cachetools import TTLCache

# Import cost analyzer
from cost_analyzer import CostAnalyzer
from backup_coverage import BackupCoverageAnalyzer
from actual_billing_fetcher import ActualBillingFetcher
from ai_cost_optimizer import AICostOptimizer

# -------------------------------------------------------------------------
# Logging Setup
# -------------------------------------------------------------------------
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class CorrelationIdFilter(logging.Filter):
    def filter(self, record):
        record.correlation_id = getattr(record, 'correlation_id', 'root')
        return True

handler = logging.StreamHandler()
handler.addFilter(CorrelationIdFilter())
formatter = logging.Formatter(
    '%(asctime)s [%(correlation_id)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
handler.setFormatter(formatter)
logger.addHandler(handler)

# -------------------------------------------------------------------------
# Scan Cache (30 minutes TTL)
# -------------------------------------------------------------------------
SCAN_CACHE = TTLCache(maxsize=200, ttl=1800)

# -------------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------------
CONFIG = {
    'HUB_ACCOUNT_ID': '325809079703',
    'DYNAMODB_TABLE': 'L1-Account-Groups',
    'DEFAULT_ROLE_NAME': 'ReadOnly-Cross-Account',
    'EXTERNAL_ID': 'msp-monitoring-2026',
    'MAX_CONCURRENT_ACCOUNTS': 5,      # Increased from 1 to 5
    'MAX_CONCURRENT_REGIONS_PER_ACCOUNT': 10,  # Increased from 2 to 10
    'METRIC_LOOKBACK_DAYS': 14,
    'IDLE_CPU_THRESHOLD': 10.0,
    'IDLE_NET_MB_PER_DAY': 2.0,
    'LONG_RUNNING_HOURS_PER_DAY': 20.0,
    'MAX_SCAN_TIMEOUT_SEC': 600,
}

# -------------------------------------------------------------------------
# Retry Decorator
# -------------------------------------------------------------------------
def retry(max_attempts=5, base_backoff=0.5, max_backoff=10.0):
    def decorator(func):
        def wrapper(*args, **kwargs):
            attempt = 1
            while attempt <= max_attempts:
                try:
                    return func(*args, **kwargs)
                except ClientError as e:
                    code = e.response['Error']['Code']
                    if code in ('Throttling', 'RequestLimitExceeded', 'SlowDown'):
                        sleep = min(base_backoff * (2 ** attempt), max_backoff)
                        time.sleep(sleep)
                        attempt += 1
                        continue
                    raise
                except EndpointConnectionError:
                    time.sleep(2)
                    attempt += 1
            raise RuntimeError(f"Failed after {max_attempts} retries: {func.__name__}")
        return wrapper
    return decorator

# -------------------------------------------------------------------------
# Main Scanner Class – COMPLETE
# -------------------------------------------------------------------------
class MSPMonitoringScanner:

    def __init__(self, correlation_id: str = None):
        self.correlation_id = correlation_id or str(uuid.uuid4())[:8]
        self.hub_session = boto3.Session()
        self.ddb = self.hub_session.resource('dynamodb')
        self.table = self.ddb.Table(CONFIG['DYNAMODB_TABLE'])
        self.findings: List[Dict] = []
        self.backup_analyzer = BackupCoverageAnalyzer()
        
        # Initialize Bedrock client for AI cost optimization
        try:
            self.bedrock_client = self.hub_session.client('bedrock-runtime', region_name='us-east-1')
            logger.info(f"[{self.correlation_id}] Bedrock client initialized successfully")
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Bedrock client initialization failed: {e}")
            self.bedrock_client = None
        
        logger.info(f"[{self.correlation_id}] Initialized BackupCoverageAnalyzer: {id(self.backup_analyzer)}")
        self.inventory: Dict = {
            'total_accounts_scanned': 0,
            'total_resources_discovered': 0,
            
            # EC2 Instances
            'ec2': {
                'total': 0,
                'idle': 0,
                'public_ip': 0,
                'imds_v1': 0,
                'missing_tags': 0,
                'details': []  # instanceId, region, state, type, publicIp, launchTime, tags, idle, avgCpu, imdsV1Enabled
            },
            
            # EBS Volumes
            'ebs': {
                'total': 0,
                'unattached': 0,
                'gp2': 0,
                'unencrypted': 0,
                'missing_tags': 0,
                'details': []  # volumeId, region, state, type, sizeGB, iops, encrypted, attachedInstance, tags
            },
            
            # S3 Buckets (global)
            's3': {
                'total': 0,
                'public_risk': 0,
                'no_lifecycle': 0,
                'missing_tags': 0,
                'details': []  # bucketName, creationDate, publicAccessBlocked, hasLifecycleRule, versioningEnabled, tags
            },
            
            # Lambda Functions (regional)
            'lambda': {
                'total': 0,
                'inefficient': 0,
                'details': []  # functionName, region, memoryMB, timeoutSec, runtime, lastModified, tags, avgDurationMs, inefficient
            },
            
            # RDS Instances
            'rds': {
                'total': 0,
                'public': 0,
                'unencrypted': 0,
                'missing_tags': 0,
                'details': []  # dbInstanceIdentifier, region, engine, engineVersion, status, publiclyAccessible, storageEncrypted, multiAZ, tags
            },
            
            # NAT Gateways
            'nat_gateway': {
                'total': 0,
                'details': []  # natGatewayId, region, state, subnetId, vpcId, tags, creationTime
            },
            
            # Elastic IPs (EIPs)
            'eip': {
                'total': 0,
                'unassociated': 0,
                'details': []  # publicIp, allocationId, associationId, instanceId, networkInterfaceId, region, tags
            },
            
            # Application Load Balancers (ALB / ELBv2)
            'alb': {
                'total': 0,
                'http_only': 0,
                'details': []  # loadBalancerName, arn, region, scheme, dnsName, tags, listeners
            },
            
            # Auto Scaling Groups (ASG)
            'asg': {
                'total': 0,
                'over_min': 0,
                'details': []  # autoScalingGroupName, region, minSize, maxSize, desiredCapacity, instancesCount, tags
            },
            
            # Route 53 Hosted Zones (global)
            'route53': {
                'total': 0,
                'public': 0,
                'details': []  # hostedZoneId, name, privateZone, resourceRecordSetCount, callerReference, tags
            },
            
            # CloudFront Distributions (global)
            'cloudfront': {
                'total': 0,
                'http_allowed': 0,
                'details': []  # distributionId, domainName, status, enabled, httpAllowed, lastModifiedTime, tags
            },
            
            # CloudTrail Trails (global/multi-region)
            'cloudtrail': {
                'total': 0,
                'no_multi_region': 0,
                'details': []  # name, trailARN, isMultiRegionTrail, homeRegion, includeGlobalServiceEvents, tags
            },
            
            # AWS Backup Vaults
            'backup': {
                'total': 0,
                'details': []  # backupVaultName, backupVaultArn, region, encryptionKeyArn, deletionProtection, tags
            },
            
            # DynamoDB Tables
            'dynamodb': {
                'total': 0,
                'provisioned_underused': 0,
                'details': []  # tableName, region, tableStatus, billingMode, readCapacityUnits, writeCapacityUnits, itemCount, sizeBytes, tags
            },
            
            # SQS Queues
            'sqs': {
                'total': 0,
                'high_retention': 0,
                'details': []  # queueName, queueUrl, region, approximateNumberOfMessages, retentionPeriodDays, visibilityTimeout, tags
            },
            
            # SNS Topics
            'sns': {
                'total': 0,
                'details': []  # topicArn, topicName, region, subscriptionsConfirmed, displayName, tags
            },
            
            # CloudWatch Log Groups
            'logs': {
                'total': 0,
                'never_expire': 0,
                'details': []  # logGroupName, region, retentionInDays, storedBytes, tags
            },
            
            # ECS Clusters
            'ecs': {
                'total': 0,
                'details': []  # clusterArn, clusterName, region, status, runningTasksCount, pendingTasksCount, tags
            },
            
            # EKS Clusters
            'eks': {
                'total': 0,
                'details': []  # name, arn, region, status, endpoint, publicAccessEnabled, version, tags
            },
            
            # AMIs / Snapshots
            'ami': {
                'total': 0,
                'unused_old': 0,
                'public': 0,
                'details': []  # imageId, region, creationDate, ageDays, state, public, name, tags
            },
            
            # VPCs
            'vpc': {
                'total': 0,
                'default': 0,
                'without_flow_logs': 0,
                'details': []  # vpcId, region, cidr, isDefault, tags, subnetsCount, allocatedResources
            },
            
            # Subnets
            'subnet': {
                'total': 0,
                'public': 0,
                'low_ips': 0,
                'details': []  # subnetId, vpcId, region, availabilityZone, cidr, availableIps, isPublic, tags, allocatedResources
            }
        }
        self.pillar_scores = {
            'security':   100.0,
            'cost_proxy': 100.0,
            'health':     100.0,
            'governance': 100.0,
        }
        self.scan_start = datetime.now(timezone.utc)

    @retry()
    def _discover_enabled_regions_for_account(self, target_session: boto3.Session) -> List[str]:
        """Discover regions using target account session (not hub)"""
        try:
            ec2 = target_session.client('ec2', region_name='us-east-1')
            resp = ec2.describe_regions(AllRegions=False)
            regions = [r['RegionName'] for r in resp['Regions'] if r['OptInStatus'] in ('opt-in-not-required', 'opted-in')]
            problematic_opt_in = {'ap-south-2', 'ap-southeast-3', 'ap-southeast-4', 'eu-south-2', 'eu-central-2', 'il-central-1', 'me-central-1'}
            regions = [r for r in regions if r not in problematic_opt_in]
            logger.info(f"[{self.correlation_id}] Target account enabled regions: {len(regions)} → {', '.join(regions)}")
            return regions or ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1']
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Region discovery failed for target: {e}")
            return ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-south-1']

    @retry()
    def assume_role(self, account_id: str, role_name: str) -> boto3.Session:
        """Return a fully configured boto3 session with assumed role credentials (v2 tokens for opt-in regions)"""
        sts = self.hub_session.client('sts', region_name='us-east-1', endpoint_url='https://sts.us-east-1.amazonaws.com')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        session_name = f"msp-scan-{int(time.time())}-{uuid.uuid4().hex[:8]}"
        
        try:
            response = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName=session_name,
                DurationSeconds=3600
            )
            creds = response['Credentials']
            
            logger.info(f"[{self.correlation_id}] Successfully assumed role in {account_id}. Session expires: {creds['Expiration']}")
            
            assumed_session = boto3.Session(
                aws_access_key_id=creds['AccessKeyId'],
                aws_secret_access_key=creds['SecretAccessKey'],
                aws_session_token=creds['SessionToken']
            )
            
            try:
                sts_assumed = assumed_session.client('sts')
                identity = sts_assumed.get_caller_identity()
                logger.info(f"[{self.correlation_id}] Assumed identity verified: {identity['Arn']}")
                logger.info(f"[{self.correlation_id}] Account: {identity['Account']}, UserId: {identity['UserId']}")
            except Exception as e:
                logger.error(f"[{self.correlation_id}] STS identity verification FAILED after assume: {e}")
                raise
            
            return assumed_session
            
        except ClientError as e:
            code = e.response['Error']['Code']
            msg = e.response['Error']['Message']
            logger.error(f"[{self.correlation_id}] AssumeRole failed: {code} - {msg}")
            if code in ('AccessDenied', 'NoSuchEntity'):
                self.findings.append({
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                    'accountId': account_id,
                    'severity': 'Critical',
                    'title': f"Cannot assume role {role_name}",
                    'description': f"{msg} – check role exists and trust policy allows hub {CONFIG['HUB_ACCOUNT_ID']}",
                    'category': 'access'
                })
            raise

    def load_all_accounts(self) -> List[Dict]:
        try:
            items = []
            scan_kwargs = {}
            while True:
                response = self.table.scan(**scan_kwargs)
                items.extend(response.get('Items', []))
                if 'LastEvaluatedKey' not in response:
                    break
                scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            logger.info(f"[{self.correlation_id}] Loaded {len(items)} accounts from table {CONFIG['DYNAMODB_TABLE']}")
            
            # Debug: Log first item to see actual attribute names
            if items:
                logger.info(f"[{self.correlation_id}] Sample DynamoDB item keys: {list(items[0].keys())}")
            
            return items
        except ClientError as e:
            logger.error(f"[{self.correlation_id}] DynamoDB scan failed: {e}")
            self.findings.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'severity': 'Critical',
                'title': 'DynamoDB access failure',
                'description': str(e),
                'category': 'system'
            })
            return []

    def _validate_tags(self, account_id: str, region: str, res_type: str, res_id: str, tags: List[Dict]):
        """Required method for tag validation – now added"""
        required = {'Owner', 'Environment', 'Project'}
        present = {t.get('Key') for t in tags or []}
        missing = required - present
        if missing:
            self.findings.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'accountId': account_id,
                'region': region,
                'resourceType': res_type,
                'resourceId': res_id,
                'severity': 'Medium',
                'title': f"{res_type} {res_id} missing tags: {', '.join(missing)}",
                'description': f"Missing: {', '.join(missing)} – governance violation",
                'category': 'governance'
            })
            self.pillar_scores['governance'] -= 8

    def execute_full_scan(self) -> Dict[str, Any]:
        start_time = time.time()
        logger.info(f"[{self.correlation_id}] Starting full scan – hub {CONFIG['HUB_ACCOUNT_ID']}")

        accounts = self.load_all_accounts()
        if not accounts:
            return {'status': 'error', 'message': 'No accounts in DynamoDB table'}

        self.inventory['total_accounts_scanned'] = len(accounts)

        with ThreadPoolExecutor(max_workers=CONFIG['MAX_CONCURRENT_ACCOUNTS']) as executor:
            futures = [executor.submit(self._process_account, acc) for acc in accounts]
            for future in as_completed(futures, timeout=CONFIG['MAX_SCAN_TIMEOUT_SEC']):
                try:
                    future.result(timeout=60)
                except Exception as exc:
                    logger.error(f"[{self.correlation_id}] Account-level exception: {exc}")

        duration = round(time.time() - start_time, 2)

        global_score = max(0, min(100, int(
            self.pillar_scores['security']   * 0.35 +
            self.pillar_scores['cost_proxy'] * 0.30 +
            self.pillar_scores['health']     * 0.20 +
            self.pillar_scores['governance'] * 0.15
        )))

        return {
            'status': 'success',
            'scanFinishedAt': datetime.now(timezone.utc).isoformat(),
            'durationSeconds': duration,
            'accountsScanned': len(accounts),
            'globalHealthScore': global_score,
            'pillarScores': {k: round(v, 1) for k, v in self.pillar_scores.items()},
            'totalFindings': len(self.findings),
            'criticalHighCount': len([f for f in self.findings if f['severity'] in ('Critical', 'High')]),
            'findings': self.findings,
            
            # Backup coverage data
            'backupCoverage': self.backup_analyzer.get_coverage_summary(),
            
            # Counts only (no details)
            'inventorySummary': {
                k: {sk: sv for sk, sv in v.items() if sk != 'details'} if isinstance(v, dict) else v
                for k, v in self.inventory.items()
                if k not in ('total_accounts_scanned', 'total_resources_discovered')
            },
            
            # Full data with details arrays
            'inventoryDetails': self.inventory
        }

    def _process_account(self, account: Dict):
        try:
            if not isinstance(account, dict):
                raise TypeError(f"Expected dict, got {type(account).__name__}: {account}")
            
            account_id = account.get('AccountID')
            if not account_id:
                raise ValueError(f"Missing 'AccountID' in item: {account}")

            role_name = CONFIG['DEFAULT_ROLE_NAME']

            logger.info(f"[{self.correlation_id}] Processing account {account_id} with role {role_name}")

            session = self.assume_role(account_id, role_name)
            
            # Scan GLOBAL services ONCE (before region loop)
            self._scan_s3_global_detailed(session, account_id)
            self._scan_route53_global_detailed(session, account_id)
            self._scan_cloudfront_global_detailed(session, account_id)
            self._scan_cloudtrail_global_detailed(session, account_id)
            
            regions_for_account = self._discover_enabled_regions_for_account(session)

            with ThreadPoolExecutor(max_workers=CONFIG['MAX_CONCURRENT_REGIONS_PER_ACCOUNT']) as executor:
                region_futures = [
                    executor.submit(self._scan_region, session, account_id, region)
                    for region in regions_for_account
                ]

                for future in as_completed(region_futures, timeout=CONFIG['MAX_SCAN_TIMEOUT_SEC']):
                    try:
                        future.result(timeout=30)
                    except Exception as e:
                        logger.warning(f"[{self.correlation_id}] Region error in {account_id}: {e}")

        except Exception as e:
            failed_id = account.get('AccountID', 'unknown') if isinstance(account, dict) else 'unknown'
            logger.error(f"[{self.correlation_id}] Account {failed_id} failed: {str(e)}")
            self.findings.append({
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'accountId': failed_id,
                'severity': 'Critical',
                'title': "Account scan failure",
                'description': f"{str(e)} – check role trust policy, permissions, or DynamoDB item",
                'category': 'system'
            })
    def _scan_region(self, session: boto3.Session, account_id: str, region: str):
        """Scan one region – ALL services"""
        logger.info(f"[{self.correlation_id}] STARTING region scan: {region} for account {account_id}")
        
        # Create clients with individual error handling
        try:
            ec2 = session.client('ec2', region_name=region)
            logger.info(f"[{self.correlation_id}] EC2 client OK in {region}")
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create EC2 client in {region}: {e}")
            ec2 = None

        try:
            cw = session.client('cloudwatch', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create CloudWatch client in {region}: {e}")
            cw = None

        try:
            s3 = session.client('s3')
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create S3 client: {e}")
            s3 = None

        try:
            rds = session.client('rds', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create RDS client in {region}: {e}")
            rds = None

        try:
            lam = session.client('lambda', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create Lambda client in {region}: {e}")
            lam = None

        try:
            elb = session.client('elbv2', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create ELB client in {region}: {e}")
            elb = None

        try:
            asg = session.client('autoscaling', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create ASG client in {region}: {e}")
            asg = None

        try:
            r53 = session.client('route53')
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create Route53 client: {e}")
            r53 = None

        try:
            logs = session.client('logs', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create Logs client in {region}: {e}")
            logs = None

        try:
            backup = session.client('backup', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create Backup client in {region}: {e}")
            backup = None

        try:
            ddb = session.client('dynamodb', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create DynamoDB client in {region}: {e}")
            ddb = None

        try:
            sqs = session.client('sqs', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create SQS client in {region}: {e}")
            sqs = None

        try:
            sns = session.client('sns', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create SNS client in {region}: {e}")
            sns = None

        try:
            cf = session.client('cloudfront')
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create CloudFront client: {e}")
            cf = None

        try:
            ct = session.client('cloudtrail', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create CloudTrail client in {region}: {e}")
            ct = None

        try:
            ecs = session.client('ecs', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create ECS client in {region}: {e}")
            ecs = None

        try:
            eks = session.client('eks', region_name=region)
        except Exception as e:
            logger.warning(f"[{self.correlation_id}] Cannot create EKS client in {region}: {e}")
            eks = None

        # Scan each service independently
        if ec2 and cw:
            try:
                self._scan_ec2_and_ebs(ec2, cw, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] EC2/EBS scan failed in {region}: {e}")

        # S3 is now scanned globally in _process_account

        if rds and cw:
            try:
                self._scan_rds(rds, cw, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] RDS scan failed in {region}: {e}")

        if lam and cw:
            try:
                self._scan_lambda(lam, cw, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] Lambda scan failed in {region}: {e}")

        if elb:
            try:
                self._scan_elb(elb, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] ELB scan failed in {region}: {e}")

        if ec2 and cw:
            try:
                self._scan_nat_gateways(ec2, cw, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] NAT Gateway scan failed in {region}: {e}")

        if ec2:
            try:
                self._scan_elastic_ips(ec2, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] EIP scan failed in {region}: {e}")

        if asg:
            try:
                self._scan_asg(asg, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] ASG scan failed in {region}: {e}")

        # Route53 is now scanned globally in _process_account

        if logs:
            try:
                self._scan_cloudwatch_logs(logs, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] CloudWatch Logs scan failed in {region}: {e}")

        if backup:
            try:
                self._scan_aws_backup(backup, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] Backup scan failed in {region}: {e}")

        if ec2:
            try:
                self._scan_amis_and_snapshots(ec2, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] AMI/Snapshot scan failed in {region}: {e}")

        if ddb:
            try:
                self._scan_dynamodb(ddb, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] DynamoDB scan failed in {region}: {e}")

        if sqs:
            try:
                self._scan_sqs(sqs, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] SQS scan failed in {region}: {e}")

        if sns:
            try:
                self._scan_sns(sns, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] SNS scan failed in {region}: {e}")

        if ec2:
            try:
                self._scan_vpc_endpoints(ec2, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] VPC Endpoints scan failed in {region}: {e}")
        
        if ec2:
            try:
                self._scan_vpcs_and_subnets(ec2, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] VPC/Subnet scan failed in {region}: {e}")

        # CloudFront is now scanned globally in _process_account

        # CloudTrail is now scanned globally in _process_account

        if ecs and ec2 and cw:
            try:
                self._scan_ecs(ecs, ec2, cw, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] ECS scan failed in {region}: {e}")

        if eks:
            try:
                self._scan_eks(eks, account_id, region)
            except Exception as e:
                logger.error(f"[{self.correlation_id}] EKS scan failed in {region}: {e}")

        logger.info(f"[{self.correlation_id}] COMPLETED region scan: {region}")

    # -------------------------------------------------------------------------
    # ALL SERVICE SCAN METHODS (original + new)
    # -------------------------------------------------------------------------

    def _scan_ec2_and_ebs(self, ec2, cw, account_id: str, region: str):
        """Scan EC2 instances and EBS volumes - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting EC2 + EBS scan in {region}")
        try:
            # EC2 Instances
            instances_found = 0
            paginator = ec2.get_paginator('describe_instances')
            for page in paginator.paginate():
                for res in page['Reservations']:
                    for inst in res['Instances']:
                        instances_found += 1
                        iid = inst['InstanceId']
                        state = inst['State']['Name']
                        inst_type = inst['InstanceType']
                        public_ip = inst.get('PublicIpAddress')
                        launch_time = inst.get('LaunchTime')
                        tags = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                        instance_name = tags.get('Name', 'N/A')  # Extract Name tag
                        
                        # Platform detection: AWS returns 'windows' for Windows, empty/None for Linux
                        platform = inst.get('Platform', '').lower()
                        if platform == 'windows':
                            os_type = 'Windows'
                        else:
                            # Check PlatformDetails for more specific info
                            platform_details = inst.get('PlatformDetails', '').lower()
                            if 'windows' in platform_details:
                                os_type = 'Windows'
                            elif 'red hat' in platform_details or 'rhel' in platform_details:
                                os_type = 'Red Hat Enterprise Linux'
                            elif 'suse' in platform_details:
                                os_type = 'SUSE Linux'
                            elif 'ubuntu' in platform_details:
                                os_type = 'Ubuntu'
                            elif 'linux' in platform_details:
                                os_type = 'Linux/UNIX'
                            else:
                                os_type = 'Linux/UNIX'  # Default

                        detail = {
                        'instanceId': iid,
                        'instanceName': instance_name,
                        'accountId': account_id,
                        'region': region,
                        'state': state,
                        'instanceType': inst_type,
                        'platform': os_type,
                        'publicIp': public_ip or None,
                        'launchTime': launch_time.isoformat() if launch_time else None,
                        'vpcId': inst.get('VpcId'),
                        'subnetId': inst.get('SubnetId'),
                        'tags': tags,
                        'idle': False,
                        'avgCpuPercent': None,
                        'imdsV1Enabled': False,
                        'hasPublicIp': bool(public_ip),
                            'scannedAt': datetime.now(timezone.utc).isoformat()
                        }

                        self.inventory['ec2']['details'].append(detail)
                        self.inventory['ec2']['total'] += 1

                        if state != 'running':
                            continue

                        # IMDSv1 check
                        try:
                            attr = ec2.describe_instance_attribute(InstanceId=iid, Attribute='metadataOptions')
                            if attr.get('MetadataOptions', {}).get('HttpTokens') == 'optional':
                                self.inventory['ec2']['imds_v1'] += 1
                                detail['imdsV1Enabled'] = True
                                self.findings.append({
                                    'severity': 'High',
                                    'title': f"IMDSv1 enabled on {iid}",
                                    'category': 'security',
                                    'resourceId': iid,
                                    'region': region
                                })
                                self.pillar_scores['security'] -= 15
                        except:
                            pass

                        # Public IP check
                        if public_ip:
                            self.inventory['ec2']['public_ip'] += 1
                            if not any(k.lower() == 'publicallowed' and v.lower() == 'true' for k, v in tags.items()):
                                self.findings.append({
                                    'severity': 'High',
                                    'title': f"Public IP on {iid} without justification",
                                    'category': 'security',
                                    'resourceId': iid,
                                    'region': region
                                })

                        # Idle check
                        try:
                            end = datetime.now(timezone.utc)
                            start = end - timedelta(days=CONFIG['METRIC_LOOKBACK_DAYS'])
                            cpu_resp = cw.get_metric_data(
                                MetricDataQueries=[{
                                    'Id': 'cpu',
                                    'MetricStat': {
                                        'Metric': {
                                            'Namespace': 'AWS/EC2',
                                            'MetricName': 'CPUUtilization',
                                            'Dimensions': [{'Name': 'InstanceId', 'Value': iid}]
                                        },
                                        'Period': 3600,
                                        'Stat': 'Average'
                                    },
                                    'ReturnData': True
                                }],
                                StartTime=start,
                                EndTime=end
                            )
                            cpu_vals = cpu_resp['MetricDataResults'][0].get('Values', [])
                            if cpu_vals:
                                avg_cpu = sum(cpu_vals) / len(cpu_vals)
                                detail['avgCpuPercent'] = round(avg_cpu, 2)
                                if avg_cpu < CONFIG['IDLE_CPU_THRESHOLD']:
                                    self.inventory['ec2']['idle'] += 1
                                    detail['idle'] = True
                                    self.findings.append({
                                        'severity': 'Medium',
                                        'title': f"Idle EC2 {iid} – {avg_cpu:.1f}% avg CPU",
                                        'category': 'cost',
                                        'resourceId': iid,
                                        'region': region
                                    })
                                    self.pillar_scores['cost_proxy'] -= 8
                        except:
                            pass

            logger.info(f"[{self.correlation_id}] EC2 scan in {region}: {instances_found} instances")

            # EBS Volumes
            volumes = ec2.describe_volumes()['Volumes']
            logger.info(f"[{self.correlation_id}] EBS scan in {region}: {len(volumes)} volumes")

            for vol in volumes:
                vol_id = vol['VolumeId']
                state = vol['State']
                vol_type = vol['VolumeType']
                size = vol['Size']
                encrypted = vol.get('Encrypted', False)
                attachments = vol.get('Attachments', [])
                tags = {t['Key']: t['Value'] for t in vol.get('Tags', [])}

                detail = {
                    'volumeId': vol_id,
                    'region': region,
                    'state': state,
                    'type': vol_type,
                    'sizeGB': size,
                    'iops': vol.get('Iops'),
                    'encrypted': encrypted,
                    'attached': bool(attachments),
                    'attachedInstanceId': attachments[0]['InstanceId'] if attachments else None,
                    'tags': tags,
                    'unattached': state == 'available',
                    'gp2': vol_type == 'gp2',
                    'unencrypted': not encrypted,
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['ebs']['details'].append(detail)
                self.inventory['ebs']['total'] += 1

                if state == 'available':
                    self.inventory['ebs']['unattached'] += 1
                    self.findings.append({
                        'severity': 'Medium',
                        'title': f"Unattached EBS {vol_id}",
                        'category': 'cost',
                        'resourceId': vol_id,
                        'region': region
                    })
                    self.pillar_scores['cost_proxy'] -= 8

                if vol_type == 'gp2':
                    self.inventory['ebs']['gp2'] += 1
                    self.findings.append({
                        'severity': 'Low',
                        'title': f"Legacy gp2 volume {vol_id}",
                        'category': 'cost',
                        'resourceId': vol_id,
                        'region': region
                    })
                    self.pillar_scores['cost_proxy'] -= 3

                if not encrypted:
                    self.inventory['ebs']['unencrypted'] += 1
                    self.findings.append({
                        'severity': 'High',
                        'title': f"Unencrypted EBS {vol_id}",
                        'category': 'security',
                        'resourceId': vol_id,
                        'region': region
                    })
                    self.pillar_scores['security'] -= 10

        except ClientError as e:
            code = e.response['Error']['Code']
            if code not in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId'):
                logger.error(f"EC2/EBS scan failed {region}: {e}")
        except Exception as e:
            logger.error(f"EC2/EBS scan failed {region}: {e}")

    def _scan_lambda(self, lam_client, cw_client, account_id: str, region: str):
        """Scan Lambda functions - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting Lambda scan in {region}")
        try:
            functions_found = 0
            paginator = lam_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for fn in page['Functions']:
                    functions_found += 1
                    fn_name = fn['FunctionName']
                    memory = fn['MemorySize']
                    timeout = fn['Timeout']
                    runtime = fn.get('Runtime', 'unknown')
                    last_modified = fn.get('LastModified')

                    detail = {
                        'functionName': fn_name,
                        'region': region,
                        'memoryMB': memory,
                        'timeoutSec': timeout,
                        'runtime': runtime,
                        'lastModified': last_modified,
                        'tags': fn.get('Tags', {}),
                        'avgDurationMs': None,
                        'inefficient': False,
                        'reason': None,
                        'scannedAt': datetime.now(timezone.utc).isoformat()
                    }

                    self.inventory['lambda']['details'].append(detail)
                    self.inventory['lambda']['total'] += 1

                    # Check duration metrics
                    try:
                        end = datetime.now(timezone.utc)
                        start = end - timedelta(days=CONFIG['METRIC_LOOKBACK_DAYS'])
                        duration_resp = cw_client.get_metric_data(
                            MetricDataQueries=[{
                                'Id': 'duration',
                                'MetricStat': {
                                    'Metric': {
                                        'Namespace': 'AWS/Lambda',
                                        'MetricName': 'Duration',
                                        'Dimensions': [{'Name': 'FunctionName', 'Value': fn_name}]
                                    },
                                    'Period': 86400,
                                    'Stat': 'Average'
                                },
                                'ReturnData': True
                            }],
                            StartTime=start,
                            EndTime=end
                        )
                        durations = duration_resp['MetricDataResults'][0].get('Values', [])
                        if durations:
                            avg_duration_ms = sum(durations) / len(durations)
                            detail['avgDurationMs'] = round(avg_duration_ms, 2)
                            if avg_duration_ms > 500 and memory <= 256:
                                self.inventory['lambda']['inefficient'] += 1
                                detail['inefficient'] = True
                                detail['reason'] = f"{avg_duration_ms:.0f}ms avg at {memory}MB"
                                self.findings.append({
                                    'severity': 'Medium',
                                    'title': f"Lambda {fn_name} inefficient",
                                    'category': 'cost',
                                    'resourceId': fn_name,
                                    'region': region
                                })
                                self.pillar_scores['cost_proxy'] -= 6
                    except:
                        pass

            logger.info(f"[{self.correlation_id}] Lambda scan in {region}: {functions_found} functions")

        except Exception as e:
            logger.error(f"Lambda scan error {region}: {e}")

    def _scan_rds(self, rds, cw, account_id: str, region: str):
        """Scan RDS instances - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting RDS scan in {region}")
        try:
            instances = rds.describe_db_instances()['DBInstances']
            logger.info(f"[{self.correlation_id}] RDS scan in {region}: {len(instances)} instances")

            for db in instances:
                db_id = db['DBInstanceIdentifier']
                engine = db['Engine']
                engine_version = db['EngineVersion']
                status = db['DBInstanceStatus']
                publicly_accessible = db.get('PubliclyAccessible', False)
                storage_encrypted = db.get('StorageEncrypted', False)
                multi_az = db.get('MultiAZ', False)
                tags = {t['Key']: t['Value'] for t in db.get('TagList', [])}

                detail = {
                    'dbInstanceIdentifier': db_id,
                    'region': region,
                    'engine': engine,
                    'engineVersion': engine_version,
                    'status': status,
                    'publiclyAccessible': publicly_accessible,
                    'storageEncrypted': storage_encrypted,
                    'multiAZ': multi_az,
                    'vpcId': db.get('DBSubnetGroup', {}).get('VpcId'),
                    'tags': tags,
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['rds']['details'].append(detail)
                self.inventory['rds']['total'] += 1

                if publicly_accessible:
                    self.inventory['rds']['public'] += 1
                    self.findings.append({
                        'severity': 'High',
                        'title': f"RDS {db_id} is publicly accessible",
                        'category': 'security',
                        'resourceId': db_id,
                        'region': region
                    })
                    self.pillar_scores['security'] -= 20

                if not storage_encrypted:
                    self.inventory['rds']['unencrypted'] += 1
                    self.findings.append({
                        'severity': 'High',
                        'title': f"RDS {db_id} not encrypted",
                        'category': 'security',
                        'resourceId': db_id,
                        'region': region
                    })
                    self.pillar_scores['security'] -= 15

        except Exception as e:
            logger.error(f"RDS scan failed {region}: {e}")

    def _scan_s3_global_detailed(self, session: boto3.Session, account_id: str):
        """S3 global scan - collect detailed records"""
        try:
            s3 = session.client('s3')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL S3 scan")
            buckets = s3.list_buckets()['Buckets']
            logger.info(f"[{self.correlation_id}] GLOBAL S3 scan: {len(buckets)} buckets")

            for b in buckets:
                name = b['Name']
                creation_date = b.get('CreationDate')

                detail = {
                    'bucketName': name,
                    'creationDate': creation_date.isoformat() if creation_date else None,
                    'publicAccessBlocked': True,  # Default to safe
                    'hasLifecycleRule': False,
                    'versioningEnabled': False,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                # ALWAYS increment total and append detail first
                self.inventory['s3']['details'].append(detail)
                self.inventory['s3']['total'] += 1

                # Then check public access (may fail)
                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    detail['publicAccessBlocked'] = all(pab['PublicAccessBlockConfiguration'].values())
                    if not detail['publicAccessBlocked']:
                        self.inventory['s3']['public_risk'] += 1
                        self.findings.append({
                            'severity': 'High',
                            'title': f"S3 bucket {name} incomplete Block Public Access",
                            'category': 'security'
                        })
                        self.pillar_scores['security'] -= 15
                except Exception as e:
                    logger.warning(f"[{self.correlation_id}] Could not check public access for bucket {name}: {e}")
                    # If we can't check, assume it's risky
                    detail['publicAccessBlocked'] = False
                    self.inventory['s3']['public_risk'] += 1

        except Exception as e:
            logger.error(f"GLOBAL S3 scan failed: {e}")

    def _scan_nat_gateways(self, ec2_client, cw_client, account_id: str, region: str):
        """Scan NAT Gateways - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting NAT Gateway scan in {region}")
        try:
            nat_gws = ec2_client.describe_nat_gateways()['NatGateways']
            logger.info(f"[{self.correlation_id}] NAT Gateway scan: {len(nat_gws)} gateways")

            for gw in nat_gws:
                gw_id = gw['NatGatewayId']
                state = gw['State']
                subnet_id = gw.get('SubnetId')
                vpc_id = gw.get('VpcId')
                creation_time = gw.get('CreateTime')
                tags = {t['Key']: t['Value'] for t in gw.get('Tags', [])}

                detail = {
                    'natGatewayId': gw_id,
                    'region': region,
                    'state': state,
                    'subnetId': subnet_id,
                    'vpcId': vpc_id,
                    'tags': tags,
                    'creationTime': creation_time.isoformat() if creation_time else None,
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['nat_gateway']['details'].append(detail)
                self.inventory['nat_gateway']['total'] += 1

        except Exception as e:
            logger.error(f"NAT Gateway scan error {region}: {e}")

    def _scan_elastic_ips(self, ec2_client, account_id: str, region: str):
        """Scan Elastic IPs - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting EIP scan in {region}")
        try:
            eips = ec2_client.describe_addresses()['Addresses']
            logger.info(f"[{self.correlation_id}] EIP scan: {len(eips)} addresses")

            for eip in eips:
                public_ip = eip.get('PublicIp')
                alloc_id = eip.get('AllocationId')
                assoc_id = eip.get('AssociationId')
                instance_id = eip.get('InstanceId')
                network_interface_id = eip.get('NetworkInterfaceId')
                tags = {t['Key']: t['Value'] for t in eip.get('Tags', [])}

                detail = {
                    'publicIp': public_ip,
                    'allocationId': alloc_id,
                    'associationId': assoc_id,
                    'instanceId': instance_id,
                    'networkInterfaceId': network_interface_id,
                    'region': region,
                    'tags': tags,
                    'unassociated': not assoc_id,
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['eip']['details'].append(detail)
                self.inventory['eip']['total'] += 1

                if not assoc_id:
                    self.inventory['eip']['unassociated'] += 1
                    self.findings.append({
                        'severity': 'Medium',
                        'title': f"Unassociated EIP {public_ip}",
                        'category': 'cost',
                        'region': region
                    })
                    self.pillar_scores['cost_proxy'] -= 8

        except Exception as e:
            logger.error(f"EIP scan error {region}: {e}")

    def _scan_elb(self, elb_client, account_id: str, region: str):
        """Scan ALB/ELB - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting ELB scan in {region}")
        try:
            lb_count = 0
            paginator = elb_client.get_paginator('describe_load_balancers')
            for page in paginator.paginate():
                for lb in page['LoadBalancers']:
                    lb_count += 1
                    lb_name = lb['LoadBalancerName']
                    arn = lb['LoadBalancerArn']
                    scheme = lb.get('Scheme')
                    dns_name = lb.get('DNSName')

                    listeners = elb_client.describe_listeners(LoadBalancerArn=arn)['Listeners']
                    listener_protocols = [l['Protocol'] for l in listeners]

                    detail = {
                        'loadBalancerName': lb_name,
                        'arn': arn,
                        'region': region,
                        'scheme': scheme,
                        'dnsName': dns_name,
                        'tags': {},
                        'listeners': listener_protocols,
                        'scannedAt': datetime.now(timezone.utc).isoformat()
                    }

                    self.inventory['alb']['details'].append(detail)
                    self.inventory['alb']['total'] += 1

                    if 'HTTP' in listener_protocols:
                        self.inventory['alb']['http_only'] += 1
                        self.findings.append({
                            'severity': 'High',
                            'title': f"ALB {lb_name} has HTTP listener",
                            'category': 'security',
                            'region': region
                        })
                        self.pillar_scores['security'] -= 12

            logger.info(f"[{self.correlation_id}] ELB scan: {lb_count} load balancers")

        except Exception as e:
            logger.error(f"ELB scan error {region}: {e}")

    def _scan_asg(self, autoscaling_client, account_id: str, region: str):
        """Scan Auto Scaling Groups - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting ASG scan in {region}")
        try:
            asg_count = 0
            paginator = autoscaling_client.get_paginator('describe_auto_scaling_groups')
            for page in paginator.paginate():
                for asg in page['AutoScalingGroups']:
                    asg_count += 1
                    asg_name = asg['AutoScalingGroupName']
                    min_size = asg['MinSize']
                    max_size = asg['MaxSize']
                    desired = asg['DesiredCapacity']
                    instances_count = len(asg.get('Instances', []))
                    tags = {t['Key']: t['Value'] for t in asg.get('Tags', [])}

                    detail = {
                        'autoScalingGroupName': asg_name,
                        'region': region,
                        'minSize': min_size,
                        'maxSize': max_size,
                        'desiredCapacity': desired,
                        'instancesCount': instances_count,
                        'tags': tags,
                        'scannedAt': datetime.now(timezone.utc).isoformat()
                    }

                    self.inventory['asg']['details'].append(detail)
                    self.inventory['asg']['total'] += 1

                    if min_size > 0 and instances_count <= min_size:
                        self.inventory['asg']['over_min'] += 1
                        self.findings.append({
                            'severity': 'Medium',
                            'title': f"ASG {asg_name} at MinSize",
                            'category': 'cost',
                            'region': region
                        })
                        self.pillar_scores['cost_proxy'] -= 6

            logger.info(f"[{self.correlation_id}] ASG scan: {asg_count} groups")

        except Exception as e:
            logger.error(f"ASG scan error {region}: {e}")

    def _scan_route53_global_detailed(self, session: boto3.Session, account_id: str):
        """Route53 global scan - collect detailed records"""
        try:
            r53 = session.client('route53')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL Route53 scan")
            zones = r53.list_hosted_zones()['HostedZones']
            logger.info(f"[{self.correlation_id}] GLOBAL Route53 scan: {len(zones)} zones")

            for zone in zones:
                zone_id = zone['Id'].split('/')[-1]
                zone_name = zone['Name']
                private_zone = zone['Config']['PrivateZone']
                record_count = zone.get('ResourceRecordSetCount', 0)

                detail = {
                    'hostedZoneId': zone_id,
                    'name': zone_name,
                    'privateZone': private_zone,
                    'resourceRecordSetCount': record_count,
                    'callerReference': zone.get('CallerReference'),
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['route53']['details'].append(detail)
                self.inventory['route53']['total'] += 1

                if not private_zone:
                    self.inventory['route53']['public'] += 1

        except Exception as e:
            logger.error(f"GLOBAL Route53 scan failed: {e}")

    def _scan_cloudfront_global_detailed(self, session: boto3.Session, account_id: str):
        """CloudFront global scan - collect detailed records"""
        try:
            cf = session.client('cloudfront')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL CloudFront scan")
            distributions = cf.list_distributions()['DistributionList'].get('Items', [])
            logger.info(f"[{self.correlation_id}] GLOBAL CloudFront scan: {len(distributions)} distributions")

            for dist in distributions:
                dist_id = dist['Id']
                domain_name = dist['DomainName']
                status = dist['Status']
                enabled = dist['Enabled']
                last_modified = dist.get('LastModifiedTime')
                http_allowed = dist['DefaultCacheBehavior']['ViewerProtocolPolicy'] != 'redirect-to-https'

                detail = {
                    'distributionId': dist_id,
                    'domainName': domain_name,
                    'status': status,
                    'enabled': enabled,
                    'httpAllowed': http_allowed,
                    'lastModifiedTime': last_modified.isoformat() if last_modified else None,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['cloudfront']['details'].append(detail)
                self.inventory['cloudfront']['total'] += 1

                if http_allowed:
                    self.inventory['cloudfront']['http_allowed'] += 1
                    self.findings.append({
                        'severity': 'High',
                        'title': f"CloudFront {dist_id} allows HTTP",
                        'category': 'security'
                    })
                    self.pillar_scores['security'] -= 10

        except Exception as e:
            logger.error(f"GLOBAL CloudFront scan failed: {e}")

    def _scan_cloudtrail_global_detailed(self, session: boto3.Session, account_id: str):
        """CloudTrail global scan - collect detailed records"""
        try:
            ct = session.client('cloudtrail', region_name='us-east-1')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL CloudTrail scan")
            trails = ct.describe_trails()['trailList']
            logger.info(f"[{self.correlation_id}] GLOBAL CloudTrail scan: {len(trails)} trails")

            for trail in trails:
                trail_name = trail['Name']
                trail_arn = trail['TrailARN']
                is_multi_region = trail.get('IsMultiRegionTrail', False)
                home_region = trail.get('HomeRegion')
                include_global = trail.get('IncludeGlobalServiceEvents', False)

                detail = {
                    'name': trail_name,
                    'trailARN': trail_arn,
                    'isMultiRegionTrail': is_multi_region,
                    'homeRegion': home_region,
                    'includeGlobalServiceEvents': include_global,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['cloudtrail']['details'].append(detail)
                self.inventory['cloudtrail']['total'] += 1

                if not is_multi_region:
                    self.inventory['cloudtrail']['no_multi_region'] += 1

            if not any(t.get('IsMultiRegionTrail', False) for t in trails):
                self.findings.append({
                    'severity': 'High',
                    'title': "No multi-region CloudTrail trail",
                    'category': 'security'
                })
                self.pillar_scores['security'] -= 20

        except Exception as e:
            logger.error(f"GLOBAL CloudTrail scan failed: {e}")

    def _scan_dynamodb(self, ddb_client, account_id: str, region: str):
        """Scan DynamoDB tables - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting DynamoDB scan in {region}")
        try:
            tables = ddb_client.list_tables()['TableNames']
            logger.info(f"[{self.correlation_id}] DynamoDB scan: {len(tables)} tables")

            for table_name in tables:
                desc = ddb_client.describe_table(TableName=table_name)['Table']
                billing_mode = desc.get('BillingModeSummary', {}).get('BillingMode', 'PROVISIONED')
                read_capacity = desc.get('ProvisionedThroughput', {}).get('ReadCapacityUnits', 0)
                write_capacity = desc.get('ProvisionedThroughput', {}).get('WriteCapacityUnits', 0)
                item_count = desc.get('ItemCount', 0)
                size_bytes = desc.get('TableSizeBytes', 0)

                detail = {
                    'tableName': table_name,
                    'region': region,
                    'tableStatus': desc['TableStatus'],
                    'billingMode': billing_mode,
                    'readCapacityUnits': read_capacity,
                    'writeCapacityUnits': write_capacity,
                    'itemCount': item_count,
                    'sizeBytes': size_bytes,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['dynamodb']['details'].append(detail)
                self.inventory['dynamodb']['total'] += 1

                if billing_mode == 'PROVISIONED':
                    self.inventory['dynamodb']['provisioned_underused'] += 1

        except Exception as e:
            logger.error(f"DynamoDB scan failed {region}: {e}")

    def _scan_sqs(self, sqs_client, account_id: str, region: str):
        """Scan SQS queues - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting SQS scan in {region}")
        try:
            queues = sqs_client.list_queues().get('QueueUrls', [])
            logger.info(f"[{self.correlation_id}] SQS scan: {len(queues)} queues")

            for q_url in queues:
                q_name = q_url.split('/')[-1]
                attrs = sqs_client.get_queue_attributes(QueueUrl=q_url, AttributeNames=['All'])['Attributes']
                retention_days = int(attrs.get('MessageRetentionPeriod', 345600)) / 86400
                msg_count = int(attrs.get('ApproximateNumberOfMessages', 0))
                visibility_timeout = int(attrs.get('VisibilityTimeout', 30))

                detail = {
                    'queueName': q_name,
                    'queueUrl': q_url,
                    'region': region,
                    'approximateNumberOfMessages': msg_count,
                    'retentionPeriodDays': round(retention_days, 1),
                    'visibilityTimeout': visibility_timeout,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['sqs']['details'].append(detail)
                self.inventory['sqs']['total'] += 1

                if retention_days > 14:
                    self.inventory['sqs']['high_retention'] += 1

        except Exception as e:
            logger.error(f"SQS scan failed {region}: {e}")

    def _scan_sns(self, sns_client, account_id: str, region: str):
        """Scan SNS topics - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting SNS scan in {region}")
        try:
            topics = sns_client.list_topics()['Topics']
            logger.info(f"[{self.correlation_id}] SNS scan: {len(topics)} topics")

            for topic in topics:
                arn = topic['TopicArn']
                name = arn.split(':')[-1]
                attrs = sns_client.get_topic_attributes(TopicArn=arn)['Attributes']
                subs = sns_client.list_subscriptions_by_topic(TopicArn=arn)['Subscriptions']
                confirmed_subs = len([s for s in subs if s['SubscriptionArn'] != 'PendingConfirmation'])

                detail = {
                    'topicArn': arn,
                    'topicName': name,
                    'region': region,
                    'subscriptionsConfirmed': confirmed_subs,
                    'displayName': attrs.get('DisplayName', ''),
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['sns']['details'].append(detail)
                self.inventory['sns']['total'] += 1

        except Exception as e:
            logger.error(f"SNS scan failed {region}: {e}")

    def _scan_cloudwatch_logs(self, logs_client, account_id: str, region: str):
        """Scan CloudWatch Log Groups - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting CloudWatch Logs scan in {region}")
        try:
            log_group_count = 0
            paginator = logs_client.get_paginator('describe_log_groups')
            for page in paginator.paginate():
                for lg in page['logGroups']:
                    log_group_count += 1
                    group_name = lg['logGroupName']
                    retention = lg.get('retentionInDays')
                    stored_bytes = lg.get('storedBytes', 0)

                    detail = {
                        'logGroupName': group_name,
                        'region': region,
                        'retentionInDays': retention if retention else -1,
                        'storedBytes': stored_bytes,
                        'tags': {},
                        'scannedAt': datetime.now(timezone.utc).isoformat()
                    }

                    self.inventory['logs']['details'].append(detail)
                    self.inventory['logs']['total'] += 1

                    if retention is None or retention == -1:
                        self.inventory['logs']['never_expire'] += 1

            logger.info(f"[{self.correlation_id}] CloudWatch Logs scan: {log_group_count} log groups")

        except Exception as e:
            logger.error(f"CloudWatch Logs scan error {region}: {e}")

    def _scan_ecs(self, ecs_client, ec2_client, cw_client, account_id: str, region: str):
        """Scan ECS clusters - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting ECS scan in {region}")
        try:
            clusters = ecs_client.list_clusters()['clusterArns']
            logger.info(f"[{self.correlation_id}] ECS scan: {len(clusters)} clusters")

            for cluster_arn in clusters:
                cluster_name = cluster_arn.split('/')[-1]
                desc = ecs_client.describe_clusters(clusters=[cluster_arn])['clusters'][0]
                running_tasks = desc.get('runningTasksCount', 0)
                pending_tasks = desc.get('pendingTasksCount', 0)
                status = desc.get('status', 'UNKNOWN')

                detail = {
                    'clusterArn': cluster_arn,
                    'clusterName': cluster_name,
                    'region': region,
                    'status': status,
                    'runningTasksCount': running_tasks,
                    'pendingTasksCount': pending_tasks,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['ecs']['details'].append(detail)
                self.inventory['ecs']['total'] += 1

        except Exception as e:
            logger.error(f"ECS scan failed {region}: {e}")

    def _scan_eks(self, eks_client, account_id: str, region: str):
        """Scan EKS clusters - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting EKS scan in {region}")
        try:
            clusters = eks_client.list_clusters()['clusters']
            logger.info(f"[{self.correlation_id}] EKS scan: {len(clusters)} clusters")

            for cluster_name in clusters:
                desc = eks_client.describe_cluster(name=cluster_name)['cluster']
                endpoint = desc.get('endpoint')
                public_access = desc.get('resourcesVpcConfig', {}).get('endpointPublicAccess', False)
                version = desc.get('version')
                status = desc.get('status')

                detail = {
                    'name': cluster_name,
                    'arn': desc['arn'],
                    'region': region,
                    'status': status,
                    'endpoint': endpoint,
                    'publicAccessEnabled': public_access,
                    'version': version,
                    'tags': desc.get('tags', {}),
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['eks']['details'].append(detail)
                self.inventory['eks']['total'] += 1

                if public_access:
                    self.findings.append({
                        'severity': 'High',
                        'title': f"EKS cluster {cluster_name} has public endpoint",
                        'category': 'security',
                        'region': region
                    })
                    self.pillar_scores['security'] -= 15

        except Exception as e:
            logger.error(f"EKS scan failed {region}: {e}")

    def _scan_amis_and_snapshots(self, ec2_client, account_id: str, region: str):
        """Scan AMIs - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting AMI scan in {region}")
        try:
            amis = ec2_client.describe_images(Owners=['self'])['Images']
            logger.info(f"[{self.correlation_id}] AMI scan: {len(amis)} images")

            for ami in amis:
                ami_id = ami['ImageId']
                creation_date = ami.get('CreationDate')
                state = ami.get('State')
                public = ami.get('Public', False)
                name = ami.get('Name', '')
                tags = {t['Key']: t['Value'] for t in ami.get('Tags', [])}

                age_days = 0
                if creation_date:
                    if isinstance(creation_date, str):
                        from dateutil import parser
                        creation_date = parser.parse(creation_date)
                    age_days = (datetime.now(timezone.utc) - creation_date.replace(tzinfo=timezone.utc)).days

                detail = {
                    'imageId': ami_id,
                    'region': region,
                    'creationDate': creation_date.isoformat() if creation_date else None,
                    'ageDays': age_days,
                    'state': state,
                    'public': public,
                    'name': name,
                    'tags': tags,
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['ami']['details'].append(detail)
                self.inventory['ami']['total'] += 1

                if age_days > 90:
                    self.inventory['ami']['unused_old'] += 1

                if public:
                    self.inventory['ami']['public'] += 1
                    self.findings.append({
                        'severity': 'High',
                        'title': f"Public AMI {ami_id}",
                        'category': 'security',
                        'region': region
                    })
                    self.pillar_scores['security'] -= 20

        except Exception as e:
            logger.error(f"AMI scan failed {region}: {e}")

    def _scan_aws_backup(self, backup_client, account_id: str, region: str):
        """Scan AWS Backup vaults and coverage - collect detailed records"""
        logger.info(f"[{self.correlation_id}] Starting AWS Backup scan in {region}")
        try:
            vaults = backup_client.list_backup_vaults()['BackupVaultList']
            logger.info(f"[{self.correlation_id}] AWS Backup scan: {len(vaults)} vaults")

            for vault in vaults:
                vault_name = vault['BackupVaultName']
                vault_arn = vault['BackupVaultArn']
                encryption_key = vault.get('EncryptionKeyArn')

                detail = {
                    'backupVaultName': vault_name,
                    'backupVaultArn': vault_arn,
                    'region': region,
                    'encryptionKeyArn': encryption_key,
                    'deletionProtection': False,
                    'tags': {},
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }

                self.inventory['backup']['details'].append(detail)
                self.inventory['backup']['total'] += 1
            
            # Analyze backup coverage (plans and protected resources)
            self.backup_analyzer.analyze_backup_coverage(backup_client, account_id, region)

        except Exception as e:
            logger.error(f"Backup scan failed {region}: {e}")

    def _scan_vpc_endpoints(self, ec2_client, account_id: str, region: str):
        """Scan VPC Endpoints"""
        logger.info(f"[{self.correlation_id}] Starting VPC Endpoints scan in {region}")
        try:
            endpoints = ec2_client.describe_vpc_endpoints()['VpcEndpoints']
            logger.info(f"[{self.correlation_id}] VPC Endpoints scan in {region}: {len(endpoints)} endpoints found")
        except Exception as e:
            logger.error(f"VPC Endpoints scan failed {region}: {e}")
    
    def _scan_vpcs_and_subnets(self, ec2_client, account_id: str, region: str):
        """Scan VPCs and Subnets with resource allocation mapping"""
        logger.info(f"[{self.correlation_id}] Starting VPC/Subnet scan in {region}")
        try:
            # Get all VPCs
            vpcs = ec2_client.describe_vpcs()['Vpcs']
            logger.info(f"[{self.correlation_id}] VPC scan: {len(vpcs)} VPCs")
            
            # Get all Subnets
            subnets = ec2_client.describe_subnets()['Subnets']
            logger.info(f"[{self.correlation_id}] Subnet scan: {len(subnets)} subnets")
            
            # Build resource mapping from already-scanned data
            vpc_resources = self._map_resources_to_vpcs()
            subnet_resources = self._map_resources_to_subnets()
            
            # Store VPC details with resource counts
            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                is_default = vpc.get('IsDefault', False)
                tags = {t['Key']: t['Value'] for t in vpc.get('Tags', [])}
                
                detail = {
                    'vpcId': vpc_id,
                    'vpcName': tags.get('Name', 'N/A'),
                    'region': region,
                    'cidrBlock': vpc['CidrBlock'],
                    'state': vpc.get('State', 'available'),
                    'isDefault': is_default,
                    'tags': tags,
                    'subnetsCount': len([s for s in subnets if s['VpcId'] == vpc_id]),
                    'allocatedResources': vpc_resources.get(vpc_id, {
                        'ec2': 0, 'rds': 0, 'nat': 0, 'alb': 0
                    }),
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }
                
                self.inventory['vpc']['details'].append(detail)
                self.inventory['vpc']['total'] += 1
                
                if is_default:
                    self.inventory['vpc']['default'] += 1
            
            # Store Subnet details with resource counts
            for subnet in subnets:
                subnet_id = subnet['SubnetId']
                vpc_id = subnet['VpcId']
                is_public = subnet.get('MapPublicIpOnLaunch', False)
                available_ips = subnet['AvailableIpAddressCount']
                tags = {t['Key']: t['Value'] for t in subnet.get('Tags', [])}
                
                detail = {
                    'subnetId': subnet_id,
                    'subnetName': tags.get('Name', 'N/A'),
                    'vpcId': vpc_id,
                    'region': region,
                    'availabilityZone': subnet['AvailabilityZone'],
                    'cidrBlock': subnet['CidrBlock'],
                    'availableIpAddressCount': available_ips,
                    'isPublic': is_public,
                    'tags': tags,
                    'allocatedResources': subnet_resources.get(subnet_id, {
                        'ec2': 0, 'rds': 0, 'nat': 0
                    }),
                    'scannedAt': datetime.now(timezone.utc).isoformat()
                }
                
                self.inventory['subnet']['details'].append(detail)
                self.inventory['subnet']['total'] += 1
                
                if is_public:
                    self.inventory['subnet']['public'] += 1
                
                if available_ips < 10:
                    self.inventory['subnet']['low_ips'] += 1
                    self.findings.append({
                        'severity': 'Low',
                        'title': f"Subnet {subnet_id} has low available IPs ({available_ips})",
                        'category': 'health',
                        'resourceId': subnet_id,
                        'region': region
                    })
        
        except Exception as e:
            logger.error(f"VPC/Subnet scan failed {region}: {e}")
    
    def _map_resources_to_vpcs(self) -> Dict:
        """Count resources per VPC from already-scanned data"""
        vpc_map = {}
        
        # Count EC2 instances per VPC
        for ec2 in self.inventory['ec2']['details']:
            vpc_id = ec2.get('vpcId')
            if vpc_id:
                if vpc_id not in vpc_map:
                    vpc_map[vpc_id] = {'ec2': 0, 'rds': 0, 'nat': 0, 'alb': 0}
                vpc_map[vpc_id]['ec2'] += 1
        
        # Count RDS per VPC
        for rds in self.inventory['rds']['details']:
            vpc_id = rds.get('vpcId')
            if vpc_id:
                if vpc_id not in vpc_map:
                    vpc_map[vpc_id] = {'ec2': 0, 'rds': 0, 'nat': 0, 'alb': 0}
                vpc_map[vpc_id]['rds'] += 1
        
        # Count NAT Gateways per VPC
        for nat in self.inventory['nat_gateway']['details']:
            vpc_id = nat.get('vpcId')
            if vpc_id:
                if vpc_id not in vpc_map:
                    vpc_map[vpc_id] = {'ec2': 0, 'rds': 0, 'nat': 0, 'alb': 0}
                vpc_map[vpc_id]['nat'] += 1
        
        # Count ALBs per VPC
        for alb in self.inventory['alb']['details']:
            vpc_id = alb.get('vpcId')
            if vpc_id:
                if vpc_id not in vpc_map:
                    vpc_map[vpc_id] = {'ec2': 0, 'rds': 0, 'nat': 0, 'alb': 0}
                vpc_map[vpc_id]['alb'] += 1
        
        return vpc_map
    
    def _map_resources_to_subnets(self) -> Dict:
        """Count resources per Subnet from already-scanned data"""
        subnet_map = {}
        
        # Count EC2 instances per Subnet
        for ec2 in self.inventory['ec2']['details']:
            subnet_id = ec2.get('subnetId')
            if subnet_id:
                if subnet_id not in subnet_map:
                    subnet_map[subnet_id] = {'ec2': 0, 'rds': 0, 'nat': 0}
                subnet_map[subnet_id]['ec2'] += 1
        
        # Count RDS per Subnet
        for rds in self.inventory['rds']['details']:
            subnet_id = rds.get('subnetId')
            if subnet_id:
                if subnet_id not in subnet_map:
                    subnet_map[subnet_id] = {'ec2': 0, 'rds': 0, 'nat': 0}
                subnet_map[subnet_id]['rds'] += 1
        
        # Count NAT Gateways per Subnet
        for nat in self.inventory['nat_gateway']['details']:
            subnet_id = nat.get('subnetId')
            if subnet_id:
                if subnet_id not in subnet_map:
                    subnet_map[subnet_id] = {'ec2': 0, 'rds': 0, 'nat': 0}
                subnet_map[subnet_id]['nat'] += 1
        
        return subnet_map

    # -------------------------------------------------------------------------
    # GLOBAL Service Scans (called once per account, not per region)
    # -------------------------------------------------------------------------

    def _scan_s3_global(self, session: boto3.Session, account_id: str):
        """S3 is global - scan once per account"""
        try:
            s3 = session.client('s3')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL S3 scan for {account_id}")
            buckets = s3.list_buckets()['Buckets']
            logger.info(f"[{self.correlation_id}] GLOBAL S3 scan: {len(buckets)} buckets found")

            for b in buckets:
                name = b['Name']
                self._validate_tags(account_id, 'global', "S3", name, [])

                try:
                    pab = s3.get_public_access_block(Bucket=name)
                    if not all(pab['PublicAccessBlockConfiguration'].values()):
                        self.inventory['s3']['public_risk'] += 1
                        self.findings.append({
                            'severity': 'High',
                            'title': f"S3 bucket {name} has incomplete Block Public Access",
                            'category': 'security'
                        })
                        self.pillar_scores['security'] -= 15
                except ClientError:
                    pass

        except Exception as e:
            logger.error(f"GLOBAL S3 scan failed {account_id}: {e}")

    def _scan_route53_global(self, session: boto3.Session, account_id: str):
        """Route53 is global - scan once per account"""
        try:
            r53 = session.client('route53')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL Route53 scan for {account_id}")
            zones = r53.list_hosted_zones()['HostedZones']
            logger.info(f"[{self.correlation_id}] GLOBAL Route53 scan: {len(zones)} zones found")

            for zone in zones:
                zone_id = zone['Id'].split('/')[-1]
                zone_name = zone['Name']
                if not zone['Config']['PrivateZone']:
                    self.inventory['route53']['public'] += 1
                    self.findings.append({
                        'severity': 'Medium',
                        'title': f"Public hosted zone {zone_name} ({zone_id})",
                        'description': "Review for unintended exposure",
                        'category': 'security'
                    })
                    self.pillar_scores['security'] -= 5

        except Exception as e:
            logger.error(f"GLOBAL Route53 scan failed {account_id}: {e}")

    def _scan_cloudfront_global(self, session: boto3.Session, account_id: str):
        """CloudFront is global - scan once per account"""
        try:
            cf = session.client('cloudfront')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL CloudFront scan for {account_id}")
            distributions = cf.list_distributions()['DistributionList'].get('Items', [])
            logger.info(f"[{self.correlation_id}] GLOBAL CloudFront scan: {len(distributions)} distributions found")

            for dist in distributions:
                dist_id = dist['Id']
                tags = cf.list_tags_for_resource(Resource=dist['ARN'])['Tags']['Items']
                self._validate_tags(account_id, 'global', "CloudFront", dist_id, tags)

                if dist['DefaultCacheBehavior']['ViewerProtocolPolicy'] != 'redirect-to-https':
                    self.inventory['cloudfront']['http_allowed'] += 1
                    self.findings.append({
                        'severity': 'High',
                        'title': f"CloudFront {dist_id} allows HTTP",
                        'category': 'security'
                    })
                    self.pillar_scores['security'] -= 10

        except Exception as e:
            logger.error(f"GLOBAL CloudFront scan failed {account_id}: {e}")

    def _scan_cloudtrail_global(self, session: boto3.Session, account_id: str):
        """CloudTrail multi-region check - scan once per account"""
        try:
            ct = session.client('cloudtrail', region_name='us-east-1')
            logger.info(f"[{self.correlation_id}] Starting GLOBAL CloudTrail scan for {account_id}")
            trails = ct.describe_trails()['trailList']
            logger.info(f"[{self.correlation_id}] GLOBAL CloudTrail scan: {len(trails)} trails found")

            if not any(t.get('IsMultiRegionTrail', False) for t in trails):
                self.inventory['cloudtrail']['no_multi_region'] += 1
                self.findings.append({
                    'severity': 'High',
                    'title': "No multi-region CloudTrail trail",
                    'category': 'security'
                })
                self.pillar_scores['security'] -= 20

        except Exception as e:
            logger.error(f"GLOBAL CloudTrail scan failed {account_id}: {e}")

# -------------------------------------------------------------------------
# Lambda Handler
# -------------------------------------------------------------------------
def lambda_handler(event, context):
    scanner = MSPMonitoringScanner()
    result = scanner.execute_full_scan()
    return {
        'statusCode': 200,
        'headers': {'Content-Type': 'application/json'},
        'body': json.dumps(result, default=str)
    }

# -------------------------------------------------------------------------
# Flask Local Test Server
# -------------------------------------------------------------------------
if __name__ == '__main__':
    from flask import Flask, jsonify, request
    from flask_cors import CORS
    flask_app = Flask(__name__)
    CORS(flask_app)

    @flask_app.route('/health', methods=['GET'])
    def health_check():
        """Quick health check endpoint"""
        return jsonify({'status': 'ok', 'timestamp': datetime.now(timezone.utc).isoformat()})

    @flask_app.route('/accounts', methods=['GET'])
    def list_accounts():
        """Return list of all accounts from DynamoDB"""
        try:
            scanner = MSPMonitoringScanner()
            accounts = scanner.load_all_accounts()
            return jsonify({
                'status': 'success',
                'accounts': [{'id': acc.get('AccountID'), 'name': acc.get('AccountName', 'Unnamed')} for acc in accounts]
            })
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

    @flask_app.route('/groups', methods=['GET'])
    def get_groups():
        """Return accounts grouped by GroupName (case-insensitive)"""
        try:
            scanner = MSPMonitoringScanner()
            items = scanner.load_all_accounts()
            
            from collections import defaultdict
            groups = defaultdict(list)
            
            # Helper to get attribute case-insensitively
            def get_attr(item, *possible_names):
                for name in possible_names:
                    if name in item:
                        return item[name]
                return None
            
            for item in items:
                # Try multiple case variations
                group_name = get_attr(item, 'GroupName', 'groupname', 'Groupname', 'GROUPNAME') or 'Ungrouped'
                account_id = get_attr(item, 'AccountID', 'accountid', 'AccountId', 'ACCOUNTID') or 'unknown'
                account_name = get_attr(item, 'AccountName', 'accountname', 'Accountname', 'ACCOUNTNAME') or account_id
                
                groups[group_name].append({
                    'id': account_id,
                    'name': account_name,
                    'group': group_name
                })
            
            result = []
            for group_name, acc_list in groups.items():
                result.append({
                    'groupName': group_name,
                    'accountCount': len(acc_list),
                    'accounts': acc_list
                })
            
            return jsonify({
                'status': 'success',
                'groups': result,
                'totalAccounts': len(items),
                'totalGroups': len(result)
            })
        except Exception as e:
            logger.error(f"Error fetching groups: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/scan', methods=['GET'])
    def trigger_scan():
        account_id = request.args.get('account_id')
        
        # Check cache first
        cache_key = f"scan_{account_id if account_id else 'full'}"
        if cache_key in SCAN_CACHE:
            logger.info(f"Returning CACHED scan result for {cache_key}")
            return jsonify(SCAN_CACHE[cache_key])
        
        # No cache - run fresh scan
        scanner = MSPMonitoringScanner()
        start_time = time.time()
        
        if account_id:
            # Single account scan
            logger.info(f"[{scanner.correlation_id}] Single-account scan for {account_id}")
            
            # Find account in all accounts (scan doesn't require knowing the key schema)
            all_accounts = scanner.load_all_accounts()
            account_item = next((acc for acc in all_accounts if acc.get('AccountID') == account_id), None)
            
            if not account_item:
                return jsonify({'error': f'Account {account_id} not found'}), 404
            
            scanner._process_account(account_item)
            duration = round(time.time() - start_time, 2)
            
            # Fetch ACTUAL billing from Cost Explorer API
            try:
                # Get the assumed session from the account
                assumed_session = next((acc for acc in all_accounts if acc.get('AccountID') == account_id), None)
                if assumed_session:
                    # Re-assume role to get session for Cost Explorer
                    billing_session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
                    actual_billing_fetcher = ActualBillingFetcher(billing_session)
                    actual_billing = actual_billing_fetcher.get_current_month_cost()
                    last_month_billing = actual_billing_fetcher.get_last_month_cost()
                    actual_billing['lastMonth'] = last_month_billing
                    logger.info(f"[{scanner.correlation_id}] ACTUAL billing from AWS: ${actual_billing.get('actualMonthToDate', 0):.2f} (MTD), Last Month: ${last_month_billing.get('totalCost', 0):.2f}, Forecasted: ${actual_billing.get('forecastedMonthEnd', 0):.2f}")
                else:
                    actual_billing = {'error': 'Could not get session', 'actualMonthToDate': 0.0}
            except Exception as e:
                logger.warning(f"[{scanner.correlation_id}] Could not fetch actual billing: {e}")
                actual_billing = {'error': str(e), 'actualMonthToDate': 0.0}
            
            # NOTE: AI analysis moved to separate on-demand endpoint (/ai-cost-analysis)
            # This keeps scan fast and allows AI to run only when user clicks Cost Optimization tab
            
            global_score = max(0, min(100, int(
                scanner.pillar_scores['security']   * 0.35 +
                scanner.pillar_scores['cost_proxy'] * 0.30 +
                scanner.pillar_scores['health']     * 0.20 +
                scanner.pillar_scores['governance'] * 0.15
            )))
            
            result = {
                'status': 'success',
                'scanFinishedAt': datetime.now(timezone.utc).isoformat(),
                'durationSeconds': duration,
                'accountsScanned': 1,
                'accountId': account_id,
                'globalHealthScore': global_score,
                'pillarScores': {k: round(v, 1) for k, v in scanner.pillar_scores.items()},
                'totalFindings': len(scanner.findings),
                'criticalHighCount': len([f for f in scanner.findings if f['severity'] in ('Critical', 'High')]),
                'findings': scanner.findings,
                
                # ACTUAL billing from AWS Cost Explorer
                'actualBilling': actual_billing,
                
                # Backup coverage data
                'backupCoverage': scanner.backup_analyzer.get_coverage_summary(),
                
                # Counts only (no details)
                'inventorySummary': {
                    k: {sk: sv for sk, sv in v.items() if sk != 'details'} if isinstance(v, dict) else v
                    for k, v in scanner.inventory.items()
                    if k not in ('total_accounts_scanned', 'total_resources_discovered')
                },
                
                # Full data with details arrays
                'inventoryDetails': scanner.inventory
            }
        else:
          # Full scan
            result = scanner.execute_full_scan()
        
        # Cache the result for 30 minutes
        SCAN_CACHE[cache_key] = result
        logger.info(f"Cached scan result for {cache_key}")
        
        return jsonify(result)

    # -------------------------------------------------------------------------
    # AI Cost Optimization API Endpoint (On-Demand)
    # -------------------------------------------------------------------------
    
    @flask_app.route('/ai-cost-analysis', methods=['POST', 'OPTIONS'])
    def ai_cost_analysis():
        """Generate AI-powered cost recommendations on-demand (triggered from UI)"""
        if request.method == 'OPTIONS':
            return '', 204
        
        try:
            data = request.get_json()
            account_id = data.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            logger.info(f"AI cost analysis requested for account {account_id}")
            
            # Get cached scan data
            cache_key = f"scan_{account_id if account_id else 'full'}"
            if cache_key not in SCAN_CACHE:
                return jsonify({'error': 'No scan data available. Run a scan first.'}), 404
            
            scan_data = SCAN_CACHE[cache_key]
            
            # Extract inventory and billing from cached scan
            inventory = scan_data.get('inventoryDetails', {})
            billing_data = scan_data.get('actualBilling', {})
            
            if not billing_data or billing_data.get('actualMonthToDate', 0) == 0:
                return jsonify({'error': 'No billing data available'}), 400
            
            # Initialize AI optimizer
            scanner = MSPMonitoringScanner()
            if not scanner.bedrock_client:
                return jsonify({'error': 'Bedrock not available'}), 503
            
            # Run AI analysis
            logger.info(f"Starting AI cost optimization for {account_id}...")
            from ai_cost_optimizer import AICostOptimizer
            ai_optimizer = AICostOptimizer(scanner.bedrock_client)
            ai_result = ai_optimizer.analyze(
                inventory=inventory,
                billing_data=billing_data,
                account_id=account_id
            )
            
            logger.info(f"AI analysis complete: {len(ai_result.get('recommendations', []))} recommendations")
            
            return jsonify({
                'status': 'success',
                'aiRecommendations': ai_result.get('recommendations', []),
                'aiSummary': ai_result.get('summary', {}),
                'aiModel': ai_result.get('aiModel'),
                'analysisTimestamp': ai_result.get('analysisTimestamp')
            })
            
        except Exception as e:
            logger.error(f"AI cost analysis failed: {e}")
            return jsonify({'error': str(e)}), 500

    # -------------------------------------------------------------------------
    # AI Security Analysis API Endpoint (On-Demand)
    # -------------------------------------------------------------------------
    
    @flask_app.route('/ai-security-analysis', methods=['POST', 'OPTIONS'])
    def ai_security_analysis():
        """Generate AI-powered security findings on-demand (triggered from UI)"""
        if request.method == 'OPTIONS':
            return '', 204
        
        try:
            data = request.get_json()
            account_id = data.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            logger.info(f"AI security analysis requested for account {account_id}")
            
            # Get cached scan data
            cache_key = f"scan_{account_id if account_id else 'full'}"
            if cache_key not in SCAN_CACHE:
                return jsonify({'error': 'No scan data available. Run a scan first.'}), 404
            
            scan_data = SCAN_CACHE[cache_key]
            
            # Extract inventory and billing from cached scan
            inventory = scan_data.get('inventoryDetails', {})
            billing_data = scan_data.get('actualBilling', {})
            
            # Get regions scanned
            regions_scanned = list(set(
                r.get('region') for service in inventory.values()
                if isinstance(service, dict) and 'details' in service
                for r in service['details'] if isinstance(r, dict) and 'region' in r
            ))
            
            logger.info(f"Analyzing security across {len(regions_scanned)} regions: {', '.join(sorted(regions_scanned))}")
            
            # Initialize AI security analyzer
            scanner = MSPMonitoringScanner()
            if not scanner.bedrock_client:
                return jsonify({'error': 'Bedrock not available'}), 503
            
            # Run AI security analysis
            logger.info(f"Starting AI security analysis for {account_id}...")
            from ai_security_analyzer import AISecurityAnalyzer
            ai_security = AISecurityAnalyzer(scanner.bedrock_client)
            ai_result = ai_security.analyze(
                inventory=inventory,
                billing_data=billing_data,
                account_id=account_id,
                regions_scanned=regions_scanned
            )
            
            logger.info(f"AI security analysis complete: {len(ai_result.get('findings', []))} findings")
            
            return jsonify({
                'status': 'success',
                'securityFindings': ai_result.get('findings', []),
                'securitySummary': ai_result.get('summary', {}),
                'aiModel': ai_result.get('aiModel'),
                'regionsScanned': ai_result.get('regionsScanned', []),
                'analysisTimestamp': ai_result.get('analysisTimestamp')
            })
            
        except Exception as e:
            logger.error(f"AI security analysis failed: {e}")
            return jsonify({'error': str(e)}), 500

    # -------------------------------------------------------------------------
    # CloudWatch Metrics API Endpoints (Lazy Loading)
    # -------------------------------------------------------------------------
    
    @flask_app.route('/metrics/services', methods=['GET'])
    def get_cloudwatch_services():
        """Get list of available CloudWatch services (categorized like AWS Console)"""
        try:
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            # Create a dummy session just to get the service list
            scanner = MSPMonitoringScanner()
            fetcher = CloudWatchMetricsFetcher(scanner.hub_session, 'us-east-1')
            services = fetcher.get_available_services()
            
            return jsonify({
                'status': 'success',
                'services': services
            })
        except Exception as e:
            logger.error(f"Failed to fetch services: {e}")
            return jsonify({'error': str(e)}), 500
    
    @flask_app.route('/metrics/ec2/<instance_id>', methods=['GET'])
    def get_ec2_metrics(instance_id):
        """Get CloudWatch metrics for specific EC2 instance"""
        try:
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            logger.info(f"Fetching EC2 metrics for {instance_id} in {region} for {hours} hours")
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_ec2_metrics(instance_id, hours)
            
            logger.info(f"Returning metrics: {len(metrics.get('cpuUtilization', []))} CPU points, {len(metrics.get('diskReadBytes', []))} disk points")
            
            return jsonify(metrics)
        except Exception as e:
            logger.error(f"Failed to fetch EC2 metrics: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/metrics/rds/<db_instance_id>', methods=['GET'])
    def get_rds_metrics(db_instance_id):
        """Get CloudWatch metrics for specific RDS instance"""
        try:
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_rds_metrics(db_instance_id, hours)
            
            return jsonify(metrics)
        except Exception as e:
            logger.error(f"Failed to fetch RDS metrics: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/metrics/lambda/<function_name>', methods=['GET'])
    def get_lambda_metrics(function_name):
        """Get CloudWatch metrics for specific Lambda function"""
        try:
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_lambda_metrics(function_name, hours)
            
            return jsonify(metrics)
        except Exception as e:
            logger.error(f"Failed to fetch Lambda metrics: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/metrics/alb', methods=['GET'])
    def get_alb_metrics():
        """Get CloudWatch metrics for specific ALB"""
        try:
            load_balancer_arn = request.args.get('arn')
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id or not load_balancer_arn:
                return jsonify({'error': 'account_id and arn required'}), 400
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_alb_metrics(load_balancer_arn, hours)
            
            return jsonify({
                'status': 'success',
                'metrics': metrics,
                'fetchedAt': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            logger.error(f"Failed to fetch ALB metrics: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/metrics/nat/<nat_gateway_id>', methods=['GET'])
    def get_nat_metrics(nat_gateway_id):
        """Get CloudWatch metrics for specific NAT Gateway"""
        try:
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_nat_gateway_metrics(nat_gateway_id, hours)
            
            return jsonify({
                'status': 'success',
                'metrics': metrics,
                'fetchedAt': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            logger.error(f"Failed to fetch NAT Gateway metrics: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/metrics/dynamodb/<table_name>', methods=['GET'])
    def get_dynamodb_metrics(table_name):
        """Get CloudWatch metrics for specific DynamoDB table"""
        try:
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_dynamodb_metrics(table_name, hours)
            
            return jsonify({
                'status': 'success',
                'metrics': metrics,
                'fetchedAt': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            logger.error(f"Failed to fetch DynamoDB metrics: {e}")
            return jsonify({'error': str(e)}), 500

    @flask_app.route('/metrics/ebs/<volume_id>', methods=['GET'])
    def get_ebs_metrics(volume_id):
        """Get CloudWatch metrics for specific EBS volume"""
        try:
            region = request.args.get('region', 'us-east-1')
            hours = request.args.get('hours', 24, type=int)
            account_id = request.args.get('account_id')
            
            if not account_id:
                return jsonify({'error': 'account_id required'}), 400
            
            scanner = MSPMonitoringScanner()
            session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
            
            from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
            fetcher = CloudWatchMetricsFetcher(session, region)
            metrics = fetcher.get_ebs_metrics(volume_id, hours)
            
            return jsonify({
                'status': 'success',
                'metrics': metrics,
                'fetchedAt': datetime.now(timezone.utc).isoformat()
            })
        except Exception as e:
            logger.error(f"Failed to fetch EBS metrics: {e}")
            return jsonify({'error': str(e)}), 500

    print("Starting Flask test server at http://localhost:5000")
    print("GET /groups → list account groups")
    print("GET /accounts → list all accounts")
    print("GET /scan → full scan")
    print("GET /scan?account_id=XXX → single account scan")
    print("GET /metrics/ec2/<id>?account_id=XXX&region=XXX → EC2 metrics")
    print("GET /metrics/rds/<id>?account_id=XXX&region=XXX → RDS metrics")
    print("GET /metrics/lambda/<name>?account_id=XXX&region=XXX → Lambda metrics")
    flask_app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
