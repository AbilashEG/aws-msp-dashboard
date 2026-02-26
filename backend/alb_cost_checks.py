"""
ALB Cost Optimization Checks
Analyzes Application Load Balancers for cost savings
"""

class ALBCostChecks:
    """ALB-specific cost optimization checks"""
    
    @staticmethod
    def check_http_only_alb(alb_details):
        """Check for ALBs with only HTTP listeners (could use cheaper options)"""
        recommendations = []
        
        for alb in alb_details:
            if alb.get('http_only'):
                recommendations.append({
                    'service': 'ALB',
                    'checkId': 'alb::http_only',
                    'resourceId': alb['loadBalancerName'],
                    'region': alb['region'],
                    'severity': 'Info',
                    'category': 'cost_optimization',
                    'title': 'ALB with HTTP-Only Traffic',
                    'description': f"ALB {alb['loadBalancerName']} only has HTTP listeners",
                    'recommendation': 'Consider using NLB for simple HTTP routing (cheaper) or add HTTPS for security',
                    'estimatedMonthlySavings': 0,
                    'potentialAction': 'review_alb_usage',
                    'details': {
                        'loadBalancerName': alb['loadBalancerName'],
                        'scheme': alb.get('scheme')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_all_albs(alb_details):
        """Flag all ALBs for cost review ($16-23/month each)"""
        recommendations = []
        
        for alb in alb_details:
            recommendations.append({
                'service': 'ALB',
                'checkId': 'alb::cost_review',
                'resourceId': alb['loadBalancerName'],
                'region': alb['region'],
                'severity': 'Info',
                'category': 'cost_optimization',
                'title': 'ALB Cost Review',
                'description': f"ALB {alb['loadBalancerName']} costs ~$16-23/month plus data processing fees",
                'recommendation': 'Review if ALB is still needed. Consider NLB for simpler use cases or consolidate multiple ALBs',
                'estimatedMonthlySavings': 20.0,
                'potentialAction': 'review_alb_necessity',
                'details': {
                    'loadBalancerName': alb['loadBalancerName'],
                    'dnsName': alb.get('dnsName')
                }
            })
        
        return recommendations
    
    @staticmethod
    def analyze(alb_details):
        """Run all ALB cost checks"""
        recommendations = []
        
        recommendations.extend(ALBCostChecks.check_http_only_alb(alb_details))
        recommendations.extend(ALBCostChecks.check_all_albs(alb_details))
        
        return recommendations
