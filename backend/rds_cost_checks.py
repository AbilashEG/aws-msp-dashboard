"""
RDS Cost Optimization Checks
Analyzes RDS instances for cost savings
"""

class RDSCostChecks:
    """RDS-specific cost optimization checks"""
    
    @staticmethod
    def check_idle_databases(rds_details):
        """Check for potentially idle RDS instances"""
        recommendations = []
        
        for rds in rds_details:
            # If status is 'stopped', it's idle
            if rds.get('status') == 'stopped':
                recommendations.append({
                    'service': 'RDS',
                    'checkId': 'rds::stopped_instance',
                    'resourceId': rds['dbInstanceIdentifier'],
                    'region': rds['region'],
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'Stopped RDS Instance',
                    'description': f"RDS instance {rds['dbInstanceIdentifier']} is stopped but still incurring storage costs",
                    'recommendation': 'Delete instance if no longer needed, or take final snapshot and delete',
                    'estimatedMonthlySavings': 20.0,  # Approximate storage cost
                    'potentialAction': 'delete_instance',
                    'details': {
                        'engine': rds.get('engine'),
                        'engineVersion': rds.get('engineVersion'),
                        'status': 'stopped'
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_single_az_databases(rds_details):
        """Check for single-AZ RDS instances that could be Multi-AZ"""
        recommendations = []
        
        for rds in rds_details:
            if not rds.get('multiAZ') and rds.get('status') == 'available':
                recommendations.append({
                    'service': 'RDS',
                    'checkId': 'rds::single_az',
                    'resourceId': rds['dbInstanceIdentifier'],
                    'region': rds['region'],
                    'severity': 'Info',
                    'category': 'cost_optimization',
                    'title': 'Single-AZ RDS Instance',
                    'description': f"RDS instance {rds['dbInstanceIdentifier']} is running in single-AZ mode",
                    'recommendation': 'If high availability is not required, this is cost-effective. If HA is needed, enable Multi-AZ (doubles cost)',
                    'estimatedMonthlySavings': 0,  # This is already optimized for cost
                    'potentialAction': 'review_ha_requirements',
                    'details': {
                        'engine': rds.get('engine'),
                        'multiAZ': False,
                        'publiclyAccessible': rds.get('publiclyAccessible')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(rds_details):
        """Run all RDS cost checks"""
        recommendations = []
        
        recommendations.extend(RDSCostChecks.check_idle_databases(rds_details))
        recommendations.extend(RDSCostChecks.check_single_az_databases(rds_details))
        
        return recommendations
