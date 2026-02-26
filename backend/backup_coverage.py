"""
AWS Backup Coverage Analyzer
Collects backup plans and their protected resources
"""

import logging
from datetime import datetime, timezone
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

class BackupCoverageAnalyzer:
    """Analyzes AWS Backup plans and protected resources"""
    
    def __init__(self):
        self.backup_coverage = {
            'total_plans': 0,
            'total_protected_resources': 0,
            'plans': []  # List of backup plans with their protected resources
        }
    
    def analyze_backup_coverage(self, backup_client, account_id: str, region: str):
        """
        Collect all backup plans and their protected resources
        
        Args:
            backup_client: boto3 backup client
            account_id: AWS account ID
            region: AWS region
        """
        logger.info(f"[BackupCoverage] Analyzing backup coverage in {region} for account {account_id}")
        
        try:
            # Get all backup plans
            plans_response = backup_client.list_backup_plans()
            plans = plans_response.get('BackupPlansList', [])
            
            logger.info(f"[BackupCoverage] Found {len(plans)} backup plans in {region}")
            
            if len(plans) == 0:
                logger.warning(f"[BackupCoverage] No backup plans found in {region}. This could mean:")
                logger.warning(f"  1. No plans exist in this region")
                logger.warning(f"  2. IAM permissions missing: backup:ListBackupPlans")
                logger.warning(f"  3. Plans exist in other regions only")
            
            for plan_summary in plans:
                plan_id = plan_summary['BackupPlanId']
                plan_name = plan_summary['BackupPlanName']
                
                logger.info(f"[BackupCoverage] Processing plan: {plan_name} (ID: {plan_id})")
                
                # Get detailed plan info
                try:
                    plan_detail = backup_client.get_backup_plan(BackupPlanId=plan_id)
                    
                    # Get protected resources for this plan
                    protected_resources = self._get_protected_resources(
                        backup_client, 
                        plan_id, 
                        plan_name
                    )
                    
                    plan_data = {
                        'planId': plan_id,
                        'planName': plan_name,
                        'planArn': plan_summary.get('BackupPlanArn'),
                        'region': region,
                        'accountId': account_id,
                        'versionId': plan_summary.get('VersionId'),
                        'creationDate': plan_summary.get('CreationDate').isoformat() if plan_summary.get('CreationDate') else None,
                        'lastExecutionDate': plan_summary.get('LastExecutionDate').isoformat() if plan_summary.get('LastExecutionDate') else None,
                        'protectedResourcesCount': len(protected_resources),
                        'protectedResources': protected_resources,
                        'rules': self._extract_backup_rules(plan_detail),
                        'scannedAt': datetime.now(timezone.utc).isoformat()
                    }
                    
                    self.backup_coverage['plans'].append(plan_data)
                    self.backup_coverage['total_plans'] += 1
                    self.backup_coverage['total_protected_resources'] += len(protected_resources)
                    
                    logger.info(f"[BackupCoverage] Plan '{plan_name}' protects {len(protected_resources)} resources")
                    
                except Exception as e:
                    logger.error(f"[BackupCoverage] Error getting details for plan {plan_name}: {e}")
                    continue
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            logger.error(f"[BackupCoverage] AWS API Error in {region}: {error_code} - {error_msg}")
            if error_code == 'AccessDeniedException':
                logger.error(f"[BackupCoverage] Missing IAM permission: backup:ListBackupPlans")
        except Exception as e:
            logger.error(f"[BackupCoverage] Failed to analyze backup coverage in {region}: {e}")
    
    def _get_protected_resources(self, backup_client, plan_id: str, plan_name: str):
        """Get all resources protected by a backup plan"""
        protected_resources = []
        
        try:
            # Get backup selections for this plan
            selections_response = backup_client.list_backup_selections(BackupPlanId=plan_id)
            selections = selections_response.get('BackupSelectionsList', [])
            
            for selection_summary in selections:
                selection_id = selection_summary['SelectionId']
                selection_name = selection_summary['SelectionName']
                
                try:
                    # Get detailed selection info
                    selection_detail = backup_client.get_backup_selection(
                        BackupPlanId=plan_id,
                        SelectionId=selection_id
                    )
                    
                    backup_selection = selection_detail.get('BackupSelection', {})
                    
                    # Extract resources from selection
                    resources = backup_selection.get('Resources', [])
                    
                    for resource_arn in resources:
                        resource_info = self._parse_resource_arn(resource_arn)
                        resource_info['selectionName'] = selection_name
                        resource_info['backupPlanName'] = plan_name
                        protected_resources.append(resource_info)
                    
                    # Handle ListOfTags (tag-based selections)
                    list_of_tags = backup_selection.get('ListOfTags', [])
                    if list_of_tags:
                        for tag_condition in list_of_tags:
                            protected_resources.append({
                                'resourceType': 'Tag-Based Selection',
                                'resourceId': f"Tags: {tag_condition}",
                                'resourceName': f"Resources matching tags",
                                'resourceArn': 'tag-based',
                                'selectionName': selection_name,
                                'backupPlanName': plan_name,
                                'tagCondition': tag_condition
                            })
                    
                except Exception as e:
                    logger.error(f"[BackupCoverage] Error getting selection {selection_name}: {e}")
                    continue
            
        except Exception as e:
            logger.error(f"[BackupCoverage] Error getting protected resources for plan {plan_id}: {e}")
        
        return protected_resources
    
    def _parse_resource_arn(self, resource_arn: str):
        """Parse AWS resource ARN to extract resource type and ID"""
        try:
            # ARN format: arn:aws:service:region:account-id:resource-type/resource-id
            parts = resource_arn.split(':')
            
            if len(parts) < 6:
                return {
                    'resourceType': 'Unknown',
                    'resourceId': resource_arn,
                    'resourceName': resource_arn,
                    'resourceArn': resource_arn
                }
            
            service = parts[2]
            resource_part = ':'.join(parts[5:])  # Everything after account-id
            
            # Parse resource type and ID
            if '/' in resource_part:
                resource_type, resource_id = resource_part.split('/', 1)
            else:
                resource_type = service
                resource_id = resource_part
            
            # Map service to friendly resource type
            resource_type_map = {
                'ec2': {
                    'instance': 'EC2 Instance',
                    'volume': 'EBS Volume',
                    'snapshot': 'EBS Snapshot'
                },
                'rds': {
                    'db': 'RDS Database',
                    'cluster': 'RDS Cluster',
                    'snapshot': 'RDS Snapshot'
                },
                's3': {
                    'bucket': 'S3 Bucket',
                    '*': 'S3 Bucket (All)'
                },
                'dynamodb': {
                    'table': 'DynamoDB Table'
                },
                'efs': {
                    'file-system': 'EFS File System'
                },
                'fsx': {
                    'file-system': 'FSx File System',
                    'backup': 'FSx Backup'
                },
                'ebs': {
                    'snapshot': 'EBS Snapshot',
                    'volume': 'EBS Volume'
                },
                'elasticfilesystem': {
                    'file-system': 'EFS File System'
                },
                'storagegateway': {
                    'gateway': 'Storage Gateway'
                },
                'backup': {
                    'recovery-point': 'Backup Recovery Point'
                },
                'redshift': {
                    'cluster': 'Redshift Cluster'
                },
                'neptune': {
                    'cluster': 'Neptune Cluster'
                },
                'docdb': {
                    'cluster': 'DocumentDB Cluster'
                },
                'timestream': {
                    'database': 'Timestream Database'
                },
                'sap-hana': {
                    'database': 'SAP HANA Database'
                },
                'cloudformation': {
                    'stack': 'CloudFormation Stack'
                }
            }
            
            friendly_type = resource_type_map.get(service, {}).get(resource_type, f"{service.upper()} {resource_type}")
            
            return {
                'resourceType': friendly_type,
                'resourceId': resource_id,
                'resourceName': resource_id,  # Can be enhanced with actual name lookup
                'resourceArn': resource_arn,
                'service': service
            }
            
        except Exception as e:
            logger.error(f"[BackupCoverage] Error parsing ARN {resource_arn}: {e}")
            return {
                'resourceType': 'Unknown',
                'resourceId': resource_arn,
                'resourceName': resource_arn,
                'resourceArn': resource_arn
            }
    
    def _extract_backup_rules(self, plan_detail):
        """Extract backup rules from plan detail"""
        rules = []
        
        try:
            backup_plan = plan_detail.get('BackupPlan', {})
            backup_rules = backup_plan.get('Rules', [])
            
            for rule in backup_rules:
                rules.append({
                    'ruleName': rule.get('RuleName'),
                    'scheduleExpression': rule.get('ScheduleExpression'),
                    'startWindowMinutes': rule.get('StartWindowMinutes'),
                    'completionWindowMinutes': rule.get('CompletionWindowMinutes'),
                    'lifecycle': rule.get('Lifecycle', {}),
                    'targetBackupVaultName': rule.get('TargetBackupVaultName')
                })
        
        except Exception as e:
            logger.error(f"[BackupCoverage] Error extracting backup rules: {e}")
        
        return rules
    
    def get_coverage_summary(self):
        """Get summary of backup coverage"""
        logger.info(f"[BackupCoverage] SUMMARY: {self.backup_coverage['total_plans']} plans, {self.backup_coverage['total_protected_resources']} resources, {len(self.backup_coverage['plans'])} plan objects")
        return self.backup_coverage
