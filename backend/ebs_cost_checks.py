"""
EBS Cost Optimization Checks
Analyzes EBS volumes for cost savings opportunities
"""

from cost_estimator import CostEstimator

class EBSCostChecks:
    """EBS-specific cost optimization checks"""
    
    @staticmethod
    def check_unattached_volumes(ebs_details):
        """Check for unattached EBS volumes"""
        recommendations = []
        
        for ebs in ebs_details:
            # Check if volume is unattached (state='available' or unattached flag)
            is_unattached = ebs.get('unattached') or ebs.get('state') == 'available'
            
            if is_unattached:
                savings = CostEstimator.estimate_ebs_monthly(ebs.get('type', 'gp3'), ebs.get('sizeGB', 0))
                
                recommendations.append({
                    'service': 'EBS',
                    'checkId': 'ebs::unattached_volume',
                    'resourceId': ebs['volumeId'],
                    'region': ebs['region'],
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'Unattached EBS Volume',
                    'description': f"Volume {ebs['volumeId']} ({ebs.get('sizeGB', 0)} GB) is not attached to any instance",
                    'recommendation': 'Delete volume if not needed, or create snapshot before deletion',
                    'estimatedMonthlySavings': round(savings, 2),
                    'potentialAction': 'delete_volume',
                    'details': {
                        'volumeType': ebs.get('type'),
                        'sizeGB': ebs.get('sizeGB'),
                        'state': ebs.get('state'),
                        'encrypted': ebs.get('encrypted')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_gp2_to_gp3_migration(ebs_details):
        """Check for gp2 volumes that should migrate to gp3"""
        recommendations = []
        
        for ebs in ebs_details:
            if ebs.get('type') == 'gp2':
                savings = CostEstimator.estimate_gp2_to_gp3_savings(ebs.get('sizeGB', 0))
                
                if savings > 0:
                    recommendations.append({
                        'service': 'EBS',
                        'checkId': 'ebs::gp2_to_gp3',
                        'resourceId': ebs['volumeId'],
                        'region': ebs['region'],
                        'severity': 'Low',
                        'category': 'cost_optimization',
                        'title': 'Migrate gp2 to gp3',
                        'description': f"Volume {ebs['volumeId']} using legacy gp2 type",
                        'recommendation': 'Migrate to gp3 for 20% cost savings with same or better performance',
                        'estimatedMonthlySavings': round(savings, 2),
                        'potentialAction': 'modify_volume_type',
                        'details': {
                            'currentType': 'gp2',
                            'suggestedType': 'gp3',
                            'sizeGB': ebs.get('sizeGB'),
                            'attached': ebs.get('attached')
                        }
                    })
        
        return recommendations
    
    @staticmethod
    def check_oversized_volumes(ebs_details):
        """Check for potentially oversized volumes"""
        recommendations = []
        
        for ebs in ebs_details:
            size_gb = ebs.get('sizeGB', 0)
            
            # Flag volumes larger than 1TB as potentially oversized
            if size_gb > 1000:
                recommendations.append({
                    'service': 'EBS',
                    'checkId': 'ebs::oversized_volume',
                    'resourceId': ebs['volumeId'],
                    'region': ebs['region'],
                    'severity': 'Info',
                    'category': 'cost_optimization',
                    'title': 'Large EBS Volume',
                    'description': f"Volume {ebs['volumeId']} is {size_gb} GB",
                    'recommendation': 'Review if full capacity is needed, consider archiving old data to S3',
                    'estimatedMonthlySavings': 0,  # Depends on usage
                    'potentialAction': 'review_usage',
                    'details': {
                        'sizeGB': size_gb,
                        'type': ebs.get('type'),
                        'attached': ebs.get('attached')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(ebs_details):
        """Run all EBS cost checks"""
        recommendations = []
        
        recommendations.extend(EBSCostChecks.check_unattached_volumes(ebs_details))
        recommendations.extend(EBSCostChecks.check_gp2_to_gp3_migration(ebs_details))
        recommendations.extend(EBSCostChecks.check_oversized_volumes(ebs_details))
        
        return recommendations
