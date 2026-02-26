"""
ASG Cost Optimization Checks
Analyzes Auto Scaling Groups for cost savings
"""

class ASGCostChecks:
    """ASG-specific cost optimization checks"""
    
    @staticmethod
    def check_over_min_capacity(asg_details):
        """Check for ASGs running above minimum capacity"""
        recommendations = []
        
        for asg in asg_details:
            if asg.get('over_min'):
                desired = asg.get('desiredCapacity', 0)
                min_size = asg.get('minSize', 0)
                extra_instances = desired - min_size
                
                recommendations.append({
                    'service': 'ASG',
                    'checkId': 'asg::over_min',
                    'resourceId': asg['autoScalingGroupName'],
                    'region': asg['region'],
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'ASG Running Above Minimum',
                    'description': f"ASG {asg['autoScalingGroupName']} running {desired} instances (min: {min_size})",
                    'recommendation': 'Review if extra capacity is needed 24/7. Consider scheduled scaling or reduce minimum',
                    'estimatedMonthlySavings': extra_instances * 30.0,
                    'potentialAction': 'optimize_capacity',
                    'details': {
                        'minSize': min_size,
                        'maxSize': asg.get('maxSize'),
                        'desiredCapacity': desired,
                        'extraInstances': extra_instances
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_spot_opportunities(asg_details):
        """Suggest spot instances for ASGs"""
        recommendations = []
        
        for asg in asg_details:
            recommendations.append({
                'service': 'ASG',
                'checkId': 'asg::spot_opportunity',
                'resourceId': asg['autoScalingGroupName'],
                'region': asg['region'],
                'severity': 'Info',
                'category': 'cost_optimization',
                'title': 'Spot Instance Opportunity',
                'description': f"ASG {asg['autoScalingGroupName']} could use Spot instances for 70-90% savings",
                'recommendation': 'Consider mixed instance policy with Spot instances for fault-tolerant workloads',
                'estimatedMonthlySavings': 50.0,
                'potentialAction': 'enable_spot_instances',
                'details': {
                    'currentInstances': asg.get('instancesCount', 0)
                }
            })
        
        return recommendations
    
    @staticmethod
    def analyze(asg_details):
        """Run all ASG cost checks"""
        recommendations = []
        
        recommendations.extend(ASGCostChecks.check_over_min_capacity(asg_details))
        recommendations.extend(ASGCostChecks.check_spot_opportunities(asg_details))
        
        return recommendations
