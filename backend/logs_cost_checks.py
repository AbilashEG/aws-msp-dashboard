"""
CloudWatch Logs Cost Optimization Checks
Analyzes log groups for cost savings
"""

class LogsCostChecks:
    """CloudWatch Logs-specific cost optimization checks"""
    
    @staticmethod
    def check_never_expire_logs(logs_details):
        """Check for log groups with no retention policy"""
        recommendations = []
        
        for log_group in logs_details:
            if log_group.get('never_expire'):
                recommendations.append({
                    'service': 'CloudWatch Logs',
                    'checkId': 'logs::no_retention',
                    'resourceId': log_group['logGroupName'],
                    'region': log_group['region'],
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'Log Group Without Retention Policy',
                    'description': f"Log group {log_group['logGroupName']} has no retention policy (logs never expire)",
                    'recommendation': 'Set retention policy to 7, 30, 90, or 365 days based on compliance requirements',
                    'estimatedMonthlySavings': 10.0,
                    'potentialAction': 'set_retention_policy',
                    'details': {
                        'logGroupName': log_group['logGroupName'],
                        'storedBytes': log_group.get('storedBytes', 0)
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_high_volume_logs(logs_details):
        """Check for high-volume log groups"""
        recommendations = []
        
        for log_group in logs_details:
            stored_gb = log_group.get('storedBytes', 0) / (1024**3)
            
            if stored_gb > 100:  # More than 100 GB
                recommendations.append({
                    'service': 'CloudWatch Logs',
                    'checkId': 'logs::high_volume',
                    'resourceId': log_group['logGroupName'],
                    'region': log_group['region'],
                    'severity': 'Info',
                    'category': 'cost_optimization',
                    'title': 'High-Volume Log Group',
                    'description': f"Log group {log_group['logGroupName']} storing {stored_gb:.1f} GB",
                    'recommendation': 'Consider log sampling, shorter retention, or export to S3 for cheaper long-term storage',
                    'estimatedMonthlySavings': 5.0,
                    'potentialAction': 'optimize_log_volume',
                    'details': {
                        'storedGB': round(stored_gb, 2),
                        'retentionDays': log_group.get('retentionInDays')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(logs_details):
        """Run all CloudWatch Logs cost checks"""
        recommendations = []
        
        recommendations.extend(LogsCostChecks.check_never_expire_logs(logs_details))
        recommendations.extend(LogsCostChecks.check_high_volume_logs(logs_details))
        
        return recommendations
