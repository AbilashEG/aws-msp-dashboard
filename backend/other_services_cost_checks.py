"""
Other Services Cost Optimization Checks
Analyzes SQS, SNS, Route53, CloudFront, CloudTrail, Backup for cost savings
"""

class OtherServicesCostChecks:
    """Cost checks for SQS, SNS, Route53, CloudFront, CloudTrail, Backup"""
    
    # ===== SQS Checks =====
    @staticmethod
    def check_empty_sqs_queues(sqs_details):
        """Check for empty SQS queues"""
        recommendations = []
        
        for queue in sqs_details:
            if queue.get('approximateNumberOfMessages', 0) == 0:
                recommendations.append({
                    'service': 'SQS',
                    'checkId': 'sqs::empty_queue',
                    'resourceId': queue['queueName'],
                    'region': queue['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Empty SQS Queue',
                    'description': f"Queue {queue['queueName']} has no messages",
                    'recommendation': 'Delete queue if no longer needed to reduce clutter',
                    'estimatedMonthlySavings': 0,
                    'potentialAction': 'delete_queue',
                    'details': {
                        'queueName': queue['queueName'],
                        'retentionDays': queue.get('retentionPeriodDays')
                    }
                })
        
        return recommendations
    
    # ===== SNS Checks =====
    @staticmethod
    def check_sns_no_subscriptions(sns_details):
        """Check for SNS topics with no subscriptions"""
        recommendations = []
        
        for topic in sns_details:
            if topic.get('subscriptionsConfirmed', 0) == 0:
                recommendations.append({
                    'service': 'SNS',
                    'checkId': 'sns::no_subscriptions',
                    'resourceId': topic['topicName'],
                    'region': topic['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'SNS Topic Without Subscriptions',
                    'description': f"Topic {topic['topicName']} has no confirmed subscriptions",
                    'recommendation': 'Delete topic if no longer needed',
                    'estimatedMonthlySavings': 0,
                    'potentialAction': 'delete_topic',
                    'details': {
                        'topicName': topic['topicName']
                    }
                })
        
        return recommendations
    
    # ===== Route53 Checks =====
    @staticmethod
    def check_unused_hosted_zones(route53_details):
        """Check for hosted zones with minimal records"""
        recommendations = []
        
        for zone in route53_details:
            record_count = zone.get('resourceRecordSetCount', 0)
            
            # Zones with only default NS and SOA records (typically 2 records)
            if record_count <= 2:
                recommendations.append({
                    'service': 'Route53',
                    'checkId': 'route53::minimal_records',
                    'resourceId': zone['hostedZoneId'],
                    'region': 'global',
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Route53 Zone with Minimal Records',
                    'description': f"Hosted zone {zone['name']} has only {record_count} records",
                    'recommendation': 'Delete zone if not in use ($0.50/month per zone)',
                    'estimatedMonthlySavings': 0.50,
                    'potentialAction': 'delete_hosted_zone',
                    'details': {
                        'zoneName': zone['name'],
                        'recordCount': record_count,
                        'privateZone': zone.get('privateZone')
                    }
                })
        
        return recommendations
    
    # ===== CloudFront Checks =====
    @staticmethod
    def check_disabled_cloudfront(cloudfront_details):
        """Check for disabled CloudFront distributions"""
        recommendations = []
        
        for dist in cloudfront_details:
            if not dist.get('enabled'):
                recommendations.append({
                    'service': 'CloudFront',
                    'checkId': 'cloudfront::disabled',
                    'resourceId': dist['distributionId'],
                    'region': 'global',
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Disabled CloudFront Distribution',
                    'description': f"Distribution {dist['distributionId']} is disabled",
                    'recommendation': 'Delete distribution if no longer needed',
                    'estimatedMonthlySavings': 0,
                    'potentialAction': 'delete_distribution',
                    'details': {
                        'distributionId': dist['distributionId'],
                        'domainName': dist.get('domainName')
                    }
                })
        
        return recommendations
    
    # ===== CloudTrail Checks =====
    @staticmethod
    def check_multiple_trails(cloudtrail_details):
        """Check for multiple trails in same region"""
        recommendations = []
        
        # Group trails by region
        trails_by_region = {}
        for trail in cloudtrail_details:
            region = trail.get('homeRegion', 'unknown')
            if region not in trails_by_region:
                trails_by_region[region] = []
            trails_by_region[region].append(trail)
        
        # Flag regions with multiple trails
        for region, trails in trails_by_region.items():
            if len(trails) > 1:
                recommendations.append({
                    'service': 'CloudTrail',
                    'checkId': 'cloudtrail::multiple_trails',
                    'resourceId': f"{region}_multiple_trails",
                    'region': region,
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Multiple CloudTrail Trails',
                    'description': f"Region {region} has {len(trails)} trails",
                    'recommendation': 'Consolidate trails to reduce costs (first trail free, additional trails charged)',
                    'estimatedMonthlySavings': 2.0,
                    'potentialAction': 'consolidate_trails',
                    'details': {
                        'trailCount': len(trails),
                        'trailNames': [t.get('name') for t in trails]
                    }
                })
        
        return recommendations
    
    # ===== Backup Checks =====
    @staticmethod
    def check_backup_vaults(backup_details):
        """Review backup vault costs"""
        recommendations = []
        
        for vault in backup_details:
            recommendations.append({
                'service': 'AWS Backup',
                'checkId': 'backup::vault_review',
                'resourceId': vault['backupVaultName'],
                'region': vault['region'],
                'severity': 'Info',
                'category': 'cost_optimization',
                'title': 'Backup Vault Cost Review',
                'description': f"Backup vault {vault['backupVaultName']} - review retention policies",
                'recommendation': 'Review backup retention policies and transition rules to optimize storage costs',
                'estimatedMonthlySavings': 10.0,
                'potentialAction': 'optimize_retention',
                'details': {
                    'vaultName': vault['backupVaultName']
                }
            })
        
        return recommendations
    
    # ===== Main Analyzer =====
    @staticmethod
    def analyze(sqs_details, sns_details, route53_details, cloudfront_details, cloudtrail_details, backup_details):
        """Run all other services cost checks"""
        recommendations = []
        
        if sqs_details:
            recommendations.extend(OtherServicesCostChecks.check_empty_sqs_queues(sqs_details))
        
        if sns_details:
            recommendations.extend(OtherServicesCostChecks.check_sns_no_subscriptions(sns_details))
        
        if route53_details:
            recommendations.extend(OtherServicesCostChecks.check_unused_hosted_zones(route53_details))
        
        if cloudfront_details:
            recommendations.extend(OtherServicesCostChecks.check_disabled_cloudfront(cloudfront_details))
        
        if cloudtrail_details:
            recommendations.extend(OtherServicesCostChecks.check_multiple_trails(cloudtrail_details))
        
        if backup_details:
            recommendations.extend(OtherServicesCostChecks.check_backup_vaults(backup_details))
        
        return recommendations
