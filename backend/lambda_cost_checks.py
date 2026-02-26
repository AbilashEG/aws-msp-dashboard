"""
Lambda Cost Optimization Checks
Analyzes Lambda functions for cost savings
"""

class LambdaCostChecks:
    """Lambda-specific cost optimization checks"""
    
    @staticmethod
    def check_inefficient_functions(lambda_details):
        """Check for inefficient Lambda configurations"""
        recommendations = []
        
        for lam in lambda_details:
            if lam.get('inefficient'):
                recommendations.append({
                    'service': 'Lambda',
                    'checkId': 'lambda::inefficient_config',
                    'resourceId': lam['functionName'],
                    'region': lam['region'],
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'Inefficient Lambda Configuration',
                    'description': f"Function {lam['functionName']}: {lam.get('reason', 'High duration with low memory')}",
                    'recommendation': 'Increase memory allocation for better performance/cost ratio. Lambda pricing is based on GB-seconds, so faster execution can reduce costs',
                    'estimatedMonthlySavings': 5.0,  # Approximate
                    'potentialAction': 'optimize_memory',
                    'details': {
                        'currentMemory': lam.get('memoryMB'),
                        'avgDuration': lam.get('avgDurationMs'),
                        'runtime': lam.get('runtime')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_unused_functions(lambda_details):
        """Check for potentially unused Lambda functions"""
        recommendations = []
        
        for lam in lambda_details:
            # If avgDurationMs is None, function might not be invoked
            if lam.get('avgDurationMs') is None:
                recommendations.append({
                    'service': 'Lambda',
                    'checkId': 'lambda::unused_function',
                    'resourceId': lam['functionName'],
                    'region': lam['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'Potentially Unused Lambda Function',
                    'description': f"Function {lam['functionName']} has no recent invocation metrics",
                    'recommendation': 'Review if function is still needed. Delete if unused to reduce clutter',
                    'estimatedMonthlySavings': 0,  # No cost if not invoked
                    'potentialAction': 'review_usage',
                    'details': {
                        'memoryMB': lam.get('memoryMB'),
                        'runtime': lam.get('runtime'),
                        'lastModified': lam.get('lastModified')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(lambda_details):
        """Run all Lambda cost checks"""
        recommendations = []
        
        recommendations.extend(LambdaCostChecks.check_inefficient_functions(lambda_details))
        recommendations.extend(LambdaCostChecks.check_unused_functions(lambda_details))
        
        return recommendations
