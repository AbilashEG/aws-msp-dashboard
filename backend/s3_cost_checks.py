"""
S3 Cost Optimization Checks
Analyzes S3 buckets for cost savings
"""

class S3CostChecks:
    """S3-specific cost optimization checks"""
    
    @staticmethod
    def check_no_lifecycle_policy(s3_details):
        """Check for buckets without lifecycle policies"""
        recommendations = []
        
        for bucket in s3_details:
            if not bucket.get('hasLifecycleRule'):
                recommendations.append({
                    'service': 'S3',
                    'checkId': 's3::no_lifecycle',
                    'resourceId': bucket['bucketName'],
                    'region': 'global',
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'S3 Bucket Without Lifecycle Policy',
                    'description': f"Bucket {bucket['bucketName']} has no lifecycle rules for transitioning to cheaper storage classes",
                    'recommendation': 'Configure lifecycle rules to transition old objects to S3-IA, Glacier, or Deep Archive',
                    'estimatedMonthlySavings': 15.0,
                    'potentialAction': 'configure_lifecycle',
                    'details': {
                        'bucketName': bucket['bucketName'],
                        'versioningEnabled': bucket.get('versioningEnabled')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_versioning_without_lifecycle(s3_details):
        """Check for versioned buckets without lifecycle to clean old versions"""
        recommendations = []
        
        for bucket in s3_details:
            if bucket.get('versioningEnabled') and not bucket.get('hasLifecycleRule'):
                recommendations.append({
                    'service': 'S3',
                    'checkId': 's3::versioning_no_cleanup',
                    'resourceId': bucket['bucketName'],
                    'region': 'global',
                    'severity': 'High',
                    'category': 'cost_optimization',
                    'title': 'Versioned S3 Bucket Without Cleanup',
                    'description': f"Bucket {bucket['bucketName']} has versioning enabled but no lifecycle to expire old versions",
                    'recommendation': 'Add lifecycle rule to expire noncurrent versions after 30-90 days',
                    'estimatedMonthlySavings': 25.0,
                    'potentialAction': 'add_version_expiration',
                    'details': {
                        'bucketName': bucket['bucketName'],
                        'versioningEnabled': True
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(s3_details):
        """Run all S3 cost checks"""
        recommendations = []
        
        recommendations.extend(S3CostChecks.check_no_lifecycle_policy(s3_details))
        recommendations.extend(S3CostChecks.check_versioning_without_lifecycle(s3_details))
        
        return recommendations
