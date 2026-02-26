"""
CloudWatch Metrics Fetcher
Fetches CloudWatch metrics and alarms for AWS resources on-demand
"""
import boto3
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# Cache metrics for 1 minute for near real-time data (like AWS Console)
METRICS_CACHE = TTLCache(maxsize=1000, ttl=60)


class CloudWatchMetricsFetcher:
    """Fetch CloudWatch metrics for AWS resources on-demand"""
    
    def __init__(self, session: boto3.Session, region: str):
        self.cw_client = session.client('cloudwatch', region_name=region)
        self.region = region
    
    # ========================================================================
    # SERVICE CATALOG
    # ========================================================================
    
    def get_available_services(self) -> List[Dict]:
        """Return list of services with CloudWatch metrics (categorized like AWS Console)"""
        return [
            {'id': 'ec2', 'name': 'EC2 Instances', 'namespace': 'AWS/EC2', 'icon': '🖥️'},
            {'id': 'rds', 'name': 'RDS Databases', 'namespace': 'AWS/RDS', 'icon': '🗄️'},
            {'id': 'lambda', 'name': 'Lambda Functions', 'namespace': 'AWS/Lambda', 'icon': 'λ'},
            {'id': 'alb', 'name': 'Application Load Balancers', 'namespace': 'AWS/ApplicationELB', 'icon': '⚖️'},
            {'id': 'nat', 'name': 'NAT Gateways', 'namespace': 'AWS/NATGateway', 'icon': '🌐'},
            {'id': 'dynamodb', 'name': 'DynamoDB Tables', 'namespace': 'AWS/DynamoDB', 'icon': '📊'},
            {'id': 'ebs', 'name': 'EBS Volumes', 'namespace': 'AWS/EBS', 'icon': '💾'}
        ]
    
    # ========================================================================
    # EC2 METRICS
    # ========================================================================
    
    def get_ec2_metrics(self, instance_id: str, hours: int = 24) -> Dict:
        """Get EC2 metrics: CPU, Disk, Memory only"""
        cache_key = f"ec2:{instance_id}:{hours}"
        if cache_key in METRICS_CACHE:
            logger.info(f"Returning CACHED metrics for {cache_key}")
            return METRICS_CACHE[cache_key]
        
        try:
            logger.info(f"Fetching FRESH metrics for {instance_id} in {self.region}")
            
            # First, list available metrics for this instance to see what's published
            logger.info(f"Checking available metrics for instance {instance_id}...")
            available_metrics = self.cw_client.list_metrics(
                Namespace='AWS/EC2',
                Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}]
            )
            metric_names = [m['MetricName'] for m in available_metrics.get('Metrics', [])]
            logger.info(f"Available EC2 metrics for {instance_id}: {metric_names}")
            
            if not metric_names:
                logger.warning(f"NO METRICS PUBLISHED for instance {instance_id} in region {self.region}!")
                logger.warning(f"Possible reasons: 1) Basic monitoring disabled, 2) Instance just started, 3) Wrong region")
            
            metrics = {
                'instanceId': instance_id,
                'region': self.region,
                'availableMetrics': metric_names,
                'cpuUtilization': self._get_metric(
                    'AWS/EC2', 'CPUUtilization', 
                    [{'Name': 'InstanceId', 'Value': instance_id}],
                    hours, 'Average'
                ),
                'diskReadBytes': self._get_metric(
                    'AWS/EC2', 'DiskReadBytes',
                    [{'Name': 'InstanceId', 'Value': instance_id}],
                    hours, 'Sum'
                ),
                'diskWriteBytes': self._get_metric(
                    'AWS/EC2', 'DiskWriteBytes',
                    [{'Name': 'InstanceId', 'Value': instance_id}],
                    hours, 'Sum'
                ),
                'memoryUtilization': self._get_metric(
                    'CWAgent', 'mem_used_percent',
                    [{'Name': 'InstanceId', 'Value': instance_id}],
                    hours, 'Average'
                )
            }
            
            logger.info(f"Metrics fetched successfully, caching...")
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch EC2 metrics for {instance_id}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'error': str(e)}
    
    # ========================================================================
    # RDS METRICS
    # ========================================================================
    
    def get_rds_metrics(self, db_instance_id: str, hours: int = 24) -> Dict:
        """Get all RDS metrics for a database instance"""
        cache_key = f"rds:{db_instance_id}:{hours}"
        if cache_key in METRICS_CACHE:
            return METRICS_CACHE[cache_key]
        
        try:
            metrics = {
                'dbInstanceId': db_instance_id,
                'region': self.region,
                'cpuUtilization': self._get_metric(
                    'AWS/RDS', 'CPUUtilization',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'databaseConnections': self._get_metric(
                    'AWS/RDS', 'DatabaseConnections',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'readIOPS': self._get_metric(
                    'AWS/RDS', 'ReadIOPS',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'writeIOPS': self._get_metric(
                    'AWS/RDS', 'WriteIOPS',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'freeStorageSpace': self._get_metric(
                    'AWS/RDS', 'FreeStorageSpace',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'readLatency': self._get_metric(
                    'AWS/RDS', 'ReadLatency',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'writeLatency': self._get_metric(
                    'AWS/RDS', 'WriteLatency',
                    [{'Name': 'DBInstanceIdentifier', 'Value': db_instance_id}],
                    hours, 'Average'
                ),
                'alarms': self.get_alarms_for_resource(db_instance_id)
            }
            
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch RDS metrics for {db_instance_id}: {e}")
            return {'error': str(e)}
    
    # ========================================================================
    # LAMBDA METRICS
    # ========================================================================
    
    def get_lambda_metrics(self, function_name: str, hours: int = 24) -> Dict:
        """Get all Lambda metrics for a function"""
        cache_key = f"lambda:{function_name}:{hours}"
        if cache_key in METRICS_CACHE:
            return METRICS_CACHE[cache_key]
        
        try:
            metrics = {
                'functionName': function_name,
                'region': self.region,
                'invocations': self._get_metric(
                    'AWS/Lambda', 'Invocations',
                    [{'Name': 'FunctionName', 'Value': function_name}],
                    hours, 'Sum'
                ),
                'duration': self._get_metric(
                    'AWS/Lambda', 'Duration',
                    [{'Name': 'FunctionName', 'Value': function_name}],
                    hours, 'Average'
                ),
                'errors': self._get_metric(
                    'AWS/Lambda', 'Errors',
                    [{'Name': 'FunctionName', 'Value': function_name}],
                    hours, 'Sum'
                ),
                'throttles': self._get_metric(
                    'AWS/Lambda', 'Throttles',
                    [{'Name': 'FunctionName', 'Value': function_name}],
                    hours, 'Sum'
                ),
                'concurrentExecutions': self._get_metric(
                    'AWS/Lambda', 'ConcurrentExecutions',
                    [{'Name': 'FunctionName', 'Value': function_name}],
                    hours, 'Maximum'
                ),
                'alarms': self.get_alarms_for_resource(function_name)
            }
            
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch Lambda metrics for {function_name}: {e}")
            return {'error': str(e)}
    
    # ========================================================================
    # ALB METRICS
    # ========================================================================
    
    def get_alb_metrics(self, load_balancer_arn: str, hours: int = 24) -> Dict:
        """Get all ALB metrics for a load balancer"""
        # Extract load balancer name from ARN
        # Format: arn:aws:elasticloadbalancing:region:account:loadbalancer/app/name/id
        lb_full_name = '/'.join(load_balancer_arn.split(':')[-1].split('/')[1:])
        
        cache_key = f"alb:{lb_full_name}:{hours}"
        if cache_key in METRICS_CACHE:
            return METRICS_CACHE[cache_key]
        
        try:
            metrics = {
                'loadBalancerArn': load_balancer_arn,
                'region': self.region,
                'requestCount': self._get_metric(
                    'AWS/ApplicationELB', 'RequestCount',
                    [{'Name': 'LoadBalancer', 'Value': lb_full_name}],
                    hours, 'Sum'
                ),
                'targetResponseTime': self._get_metric(
                    'AWS/ApplicationELB', 'TargetResponseTime',
                    [{'Name': 'LoadBalancer', 'Value': lb_full_name}],
                    hours, 'Average'
                ),
                'healthyHostCount': self._get_metric(
                    'AWS/ApplicationELB', 'HealthyHostCount',
                    [{'Name': 'LoadBalancer', 'Value': lb_full_name}],
                    hours, 'Average'
                ),
                'unHealthyHostCount': self._get_metric(
                    'AWS/ApplicationELB', 'UnHealthyHostCount',
                    [{'Name': 'LoadBalancer', 'Value': lb_full_name}],
                    hours, 'Average'
                ),
                'httpCode_Target_2XX_Count': self._get_metric(
                    'AWS/ApplicationELB', 'HTTPCode_Target_2XX_Count',
                    [{'Name': 'LoadBalancer', 'Value': lb_full_name}],
                    hours, 'Sum'
                ),
                'httpCode_Target_5XX_Count': self._get_metric(
                    'AWS/ApplicationELB', 'HTTPCode_Target_5XX_Count',
                    [{'Name': 'LoadBalancer', 'Value': lb_full_name}],
                    hours, 'Sum'
                ),
                'alarms': self.get_alarms_for_resource(load_balancer_arn)
            }
            
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch ALB metrics for {load_balancer_arn}: {e}")
            return {'error': str(e)}
    
    # ========================================================================
    # NAT GATEWAY METRICS
    # ========================================================================
    
    def get_nat_gateway_metrics(self, nat_gateway_id: str, hours: int = 24) -> Dict:
        """Get all NAT Gateway metrics"""
        cache_key = f"nat:{nat_gateway_id}:{hours}"
        if cache_key in METRICS_CACHE:
            return METRICS_CACHE[cache_key]
        
        try:
            metrics = {
                'natGatewayId': nat_gateway_id,
                'region': self.region,
                'bytesInFromSource': self._get_metric(
                    'AWS/NATGateway', 'BytesInFromSource',
                    [{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    hours, 'Sum'
                ),
                'bytesOutToDestination': self._get_metric(
                    'AWS/NATGateway', 'BytesOutToDestination',
                    [{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    hours, 'Sum'
                ),
                'packetsInFromSource': self._get_metric(
                    'AWS/NATGateway', 'PacketsInFromSource',
                    [{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    hours, 'Sum'
                ),
                'packetsOutToDestination': self._get_metric(
                    'AWS/NATGateway', 'PacketsOutToDestination',
                    [{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    hours, 'Sum'
                ),
                'activeConnectionCount': self._get_metric(
                    'AWS/NATGateway', 'ActiveConnectionCount',
                    [{'Name': 'NatGatewayId', 'Value': nat_gateway_id}],
                    hours, 'Maximum'
                ),
                'alarms': self.get_alarms_for_resource(nat_gateway_id)
            }
            
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch NAT Gateway metrics for {nat_gateway_id}: {e}")
            return {'error': str(e)}
    
    # ========================================================================
    # DYNAMODB METRICS
    # ========================================================================
    
    def get_dynamodb_metrics(self, table_name: str, hours: int = 24) -> Dict:
        """Get all DynamoDB metrics for a table"""
        cache_key = f"dynamodb:{table_name}:{hours}"
        if cache_key in METRICS_CACHE:
            return METRICS_CACHE[cache_key]
        
        try:
            metrics = {
                'tableName': table_name,
                'region': self.region,
                'consumedReadCapacityUnits': self._get_metric(
                    'AWS/DynamoDB', 'ConsumedReadCapacityUnits',
                    [{'Name': 'TableName', 'Value': table_name}],
                    hours, 'Sum'
                ),
                'consumedWriteCapacityUnits': self._get_metric(
                    'AWS/DynamoDB', 'ConsumedWriteCapacityUnits',
                    [{'Name': 'TableName', 'Value': table_name}],
                    hours, 'Sum'
                ),
                'userErrors': self._get_metric(
                    'AWS/DynamoDB', 'UserErrors',
                    [{'Name': 'TableName', 'Value': table_name}],
                    hours, 'Sum'
                ),
                'systemErrors': self._get_metric(
                    'AWS/DynamoDB', 'SystemErrors',
                    [{'Name': 'TableName', 'Value': table_name}],
                    hours, 'Sum'
                ),
                'alarms': self.get_alarms_for_resource(table_name)
            }
            
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch DynamoDB metrics for {table_name}: {e}")
            return {'error': str(e)}
    
    # ========================================================================
    # EBS METRICS
    # ========================================================================
    
    def get_ebs_metrics(self, volume_id: str, hours: int = 24) -> Dict:
        """Get all EBS metrics for a volume"""
        cache_key = f"ebs:{volume_id}:{hours}"
        if cache_key in METRICS_CACHE:
            return METRICS_CACHE[cache_key]
        
        try:
            metrics = {
                'volumeId': volume_id,
                'region': self.region,
                'volumeReadBytes': self._get_metric(
                    'AWS/EBS', 'VolumeReadBytes',
                    [{'Name': 'VolumeId', 'Value': volume_id}],
                    hours, 'Sum'
                ),
                'volumeWriteBytes': self._get_metric(
                    'AWS/EBS', 'VolumeWriteBytes',
                    [{'Name': 'VolumeId', 'Value': volume_id}],
                    hours, 'Sum'
                ),
                'volumeReadOps': self._get_metric(
                    'AWS/EBS', 'VolumeReadOps',
                    [{'Name': 'VolumeId', 'Value': volume_id}],
                    hours, 'Sum'
                ),
                'volumeWriteOps': self._get_metric(
                    'AWS/EBS', 'VolumeWriteOps',
                    [{'Name': 'VolumeId', 'Value': volume_id}],
                    hours, 'Sum'
                ),
                'volumeIdleTime': self._get_metric(
                    'AWS/EBS', 'VolumeIdleTime',
                    [{'Name': 'VolumeId', 'Value': volume_id}],
                    hours, 'Sum'
                ),
                'alarms': self.get_alarms_for_resource(volume_id)
            }
            
            METRICS_CACHE[cache_key] = metrics
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to fetch EBS metrics for {volume_id}: {e}")
            return {'error': str(e)}
    
    # ========================================================================
    # CLOUDWATCH ALARMS
    # ========================================================================
    
    def get_alarms_for_resource(self, resource_id: str) -> List[Dict]:
        """Get all CloudWatch alarms associated with a resource"""
        try:
            response = self.cw_client.describe_alarms()
            alarms = response.get('MetricAlarms', [])
            
            resource_alarms = []
            for alarm in alarms:
                dimensions = alarm.get('Dimensions', [])
                for dim in dimensions:
                    if resource_id in dim.get('Value', ''):
                        resource_alarms.append({
                            'alarmName': alarm['AlarmName'],
                            'state': alarm['StateValue'],
                            'stateReason': alarm.get('StateReason', ''),
                            'metricName': alarm['MetricName'],
                            'threshold': alarm.get('Threshold', 0),
                            'comparisonOperator': alarm.get('ComparisonOperator', ''),
                            'evaluationPeriods': alarm.get('EvaluationPeriods', 0),
                            'actionsEnabled': alarm.get('ActionsEnabled', False)
                        })
            
            return resource_alarms
            
        except Exception as e:
            logger.error(f"Failed to fetch alarms for {resource_id}: {e}")
            return []
    
    # ========================================================================
    # HELPER METHODS
    # ========================================================================
    
    def _get_metric(self, namespace: str, metric_name: str, 
                   dimensions: List[Dict], hours: int, statistic: str) -> List[Dict]:
        """Generic method to fetch CloudWatch metric data"""
        try:
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            
            # Use 5-minute period for near real-time data (matches AWS Console)
            # For longer time ranges, use larger periods to avoid API limits
            if hours <= 3:
                period = 300  # 5 minutes for last 3 hours (basic monitoring)
            elif hours <= 24:
                period = 300  # 5 minutes for last 24 hours
            else:
                period = 3600  # 1 hour for longer periods
            
            logger.info(f"\n{'='*60}")
            logger.info(f"CloudWatch Query Details:")
            logger.info(f"  Namespace: {namespace}")
            logger.info(f"  MetricName: {metric_name}")
            logger.info(f"  Dimensions: {dimensions}")
            logger.info(f"  StartTime: {start_time}")
            logger.info(f"  EndTime: {end_time}")
            logger.info(f"  Period: {period}s")
            logger.info(f"  Statistic: {statistic}")
            logger.info(f"  Region: {self.region}")
            logger.info(f"{'='*60}\n")
            
            response = self.cw_client.get_metric_statistics(
                Namespace=namespace,
                MetricName=metric_name,
                Dimensions=dimensions,
                StartTime=start_time,
                EndTime=end_time,
                Period=period,
                Statistics=[statistic]
            )
            
            datapoints = sorted(response.get('Datapoints', []), 
                              key=lambda x: x['Timestamp'])
            
            logger.info(f"CloudWatch returned {len(datapoints)} datapoints for {metric_name}")
            if len(datapoints) > 0:
                logger.info(f"First datapoint: {datapoints[0]}")
                logger.info(f"Last datapoint: {datapoints[-1]}")
            else:
                logger.warning(f"NO DATAPOINTS returned for {metric_name} in {namespace}!")
                logger.warning(f"This usually means: 1) Monitoring not enabled, 2) No activity, or 3) Wrong dimensions")
            
            return [{
                'timestamp': dp['Timestamp'].isoformat(),
                'value': round(dp.get(statistic, 0), 2),
                'unit': dp.get('Unit', 'None')
            } for dp in datapoints]
            
        except Exception as e:
            logger.error(f"Failed to fetch metric {metric_name}: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return []
