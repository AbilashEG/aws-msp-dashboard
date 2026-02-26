"""
EC2 Cost Optimization Checks
Analyzes EC2 instances for cost savings opportunities
"""

try:
    from accurate_cost_calculator import AccurateCostCalculator
    USE_ACCURATE_PRICING = True
except:
    from cost_estimator import CostEstimator
    USE_ACCURATE_PRICING = False

class EC2CostChecks:
    """EC2-specific cost optimization checks"""
    
    # Initialize accurate calculator if available
    _calculator = AccurateCostCalculator() if USE_ACCURATE_PRICING else None
    
    @staticmethod
    def check_idle_instances(ec2_details):
        """Check for idle EC2 instances (CPU < 10%)"""
        recommendations = []
        
        for ec2 in ec2_details:
            if ec2.get('idle'):
                instance_type = ec2.get('instanceType', 't2.micro')
                region = ec2.get('region', 'us-east-1')
                
                # Get ACCURATE cost
                if USE_ACCURATE_PRICING and EC2CostChecks._calculator:
                    savings = EC2CostChecks._calculator.get_ec2_monthly_cost(instance_type, region)
                else:
                    savings = CostEstimator.estimate_ec2_monthly(instance_type)
                
                print(f"[EC2CostCheck] Found idle instance: {ec2['instanceId']}, Type: {instance_type}, CPU: {ec2.get('avgCpuPercent')}%, Actual Savings: ${savings}/mo")
                
                recommendations.append({
                    'service': 'EC2',
                    'checkId': 'ec2::idle_instance',
                    'resourceId': ec2['instanceId'],
                    'resourceName': ec2.get('instanceId'),
                    'region': region,
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'Idle EC2 Instance',
                    'description': f"Instance {ec2['instanceId']} ({instance_type}) has average CPU utilization of {ec2.get('avgCpuPercent', 0)}% over 14 days",
                    'recommendation': 'Stop the instance if not needed, or downsize to a smaller instance type',
                    'estimatedMonthlySavings': round(savings, 2),
                    'potentialAction': 'stop_instance',
                    'details': {
                        'instanceType': instance_type,
                        'state': ec2.get('state'),
                        'avgCpu': ec2.get('avgCpuPercent'),
                        'launchTime': ec2.get('launchTime'),
                        'pricingSource': 'aws-pricing-api' if USE_ACCURATE_PRICING else 'estimated'
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_stopped_instances(ec2_details):
        """Check for stopped instances still incurring EBS costs"""
        recommendations = []
        
        for ec2 in ec2_details:
            if ec2.get('state') == 'stopped':
                # Stopped instances still pay for EBS volumes
                recommendations.append({
                    'service': 'EC2',
                    'checkId': 'ec2::stopped_instance',
                    'resourceId': ec2['instanceId'],
                    'region': ec2['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Stopped EC2 Instance',
                    'description': f"Instance {ec2['instanceId']} is stopped but still incurring EBS storage costs",
                    'recommendation': 'Terminate instance if no longer needed, or create AMI and terminate',
                    'estimatedMonthlySavings': 5.0,  # Approximate EBS cost
                    'potentialAction': 'terminate_instance',
                    'details': {
                        'instanceType': ec2.get('instanceType'),
                        'state': 'stopped'
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_old_generation_instances(ec2_details):
        """Check for older generation instance types"""
        recommendations = []
        
        old_gen_types = ['t2', 'm4', 'c4', 'r4', 'm3', 'c3', 'r3']
        
        for ec2 in ec2_details:
            instance_type = ec2.get('instanceType', '')
            instance_family = instance_type.split('.')[0] if '.' in instance_type else ''
            
            if instance_family in old_gen_types:
                recommendations.append({
                    'service': 'EC2',
                    'checkId': 'ec2::old_generation',
                    'resourceId': ec2['instanceId'],
                    'region': ec2['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Old Generation Instance Type',
                    'description': f"Instance using older generation type {instance_type}",
                    'recommendation': f"Upgrade to newer generation (e.g., t2→t3, m4→m5) for better price/performance",
                    'estimatedMonthlySavings': 10.0,  # Approximate 10-20% savings
                    'potentialAction': 'upgrade_instance_type',
                    'details': {
                        'currentType': instance_type,
                        'suggestedType': instance_type.replace(instance_family, instance_family[0] + str(int(instance_family[1]) + 1))
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(ec2_details):
        """Run all EC2 cost checks"""
        recommendations = []
        
        recommendations.extend(EC2CostChecks.check_idle_instances(ec2_details))
        recommendations.extend(EC2CostChecks.check_stopped_instances(ec2_details))
        recommendations.extend(EC2CostChecks.check_old_generation_instances(ec2_details))
        
        return recommendations
