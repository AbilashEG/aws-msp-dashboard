"""
Network Cost Optimization Checks
Analyzes EIPs, NAT Gateways for cost savings
"""

from cost_estimator import CostEstimator

class NetworkCostChecks:
    """Network resource cost optimization checks"""
    
    @staticmethod
    def check_unassociated_eips(eip_details):
        """Check for unassociated Elastic IPs"""
        recommendations = []
        
        for eip in eip_details:
            if eip.get('unassociated'):
                recommendations.append({
                    'service': 'EIP',
                    'checkId': 'eip::unassociated',
                    'resourceId': eip.get('publicIp', eip.get('allocationId')),
                    'region': eip['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Unassociated Elastic IP',
                    'description': f"Elastic IP {eip.get('publicIp')} is not associated with any resource",
                    'recommendation': 'Release EIP if not needed to avoid hourly charges',
                    'estimatedMonthlySavings': CostEstimator.EIP_UNASSOCIATED_COST,
                    'potentialAction': 'release_eip',
                    'details': {
                        'publicIp': eip.get('publicIp'),
                        'allocationId': eip.get('allocationId')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_nat_gateway_usage(nat_details):
        """Check NAT Gateway usage and suggest alternatives"""
        recommendations = []
        
        for nat in nat_details:
            recommendations.append({
                'service': 'NAT Gateway',
                'checkId': 'nat::review_usage',
                'resourceId': nat['natGatewayId'],
                'region': nat['region'],
                'severity': 'Info',
                'category': 'cost_optimization',
                'title': 'NAT Gateway Cost Review',
                'description': f"NAT Gateway {nat['natGatewayId']} costs ~$33/month plus data transfer fees",
                'recommendation': 'Review if NAT Gateway is still needed. Consider VPC endpoints for AWS services or NAT instances for lower traffic',
                'estimatedMonthlySavings': CostEstimator.NAT_GATEWAY_BASE_COST,
                'potentialAction': 'review_nat_usage',
                'details': {
                    'natGatewayId': nat['natGatewayId'],
                    'vpcId': nat.get('vpcId'),
                    'state': nat.get('state')
                }
            })
        
        return recommendations
    
    @staticmethod
    def analyze(eip_details, nat_details):
        """Run all network cost checks"""
        recommendations = []
        
        recommendations.extend(NetworkCostChecks.check_unassociated_eips(eip_details))
        recommendations.extend(NetworkCostChecks.check_nat_gateway_usage(nat_details))
        
        return recommendations
