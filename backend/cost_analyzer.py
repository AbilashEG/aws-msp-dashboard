"""
Cost Analyzer - Main Orchestrator
Coordinates all cost optimization checks across services
Inspired by AWS Service Screener v2 architecture
"""

from ec2_cost_checks import EC2CostChecks
from ebs_cost_checks import EBSCostChecks
from lambda_cost_checks import LambdaCostChecks
from network_cost_checks import NetworkCostChecks
from rds_cost_checks import RDSCostChecks
from s3_cost_checks import S3CostChecks
from alb_cost_checks import ALBCostChecks
from asg_cost_checks import ASGCostChecks
from dynamodb_cost_checks import DynamoDBCostChecks
from logs_cost_checks import LogsCostChecks
from other_services_cost_checks import OtherServicesCostChecks

class CostAnalyzer:
    """
    Main cost analyzer that orchestrates all service-specific checks
    Similar to Service Screener's advise() pattern
    """
    
    def __init__(self, inventory):
        """
        Initialize with inventory data from scanner
        
        Args:
            inventory: Dictionary containing all scanned resource details
        """
        self.inventory = inventory
        self.recommendations = []
    
    def analyze(self):
        """
        Run all cost optimization checks across all services
        Returns list of cost recommendations
        """
        self.recommendations = []
        
        # EC2 Checks
        ec2_details = self.inventory.get('ec2', {}).get('details', [])
        if ec2_details:
            ec2_recs = EC2CostChecks.analyze(ec2_details)
            self.recommendations.extend(ec2_recs)
            print(f"[CostAnalyzer] EC2: {len(ec2_details)} instances analyzed, {len(ec2_recs)} recommendations")
        
        # EBS Checks
        ebs_details = self.inventory.get('ebs', {}).get('details', [])
        if ebs_details:
            ebs_recs = EBSCostChecks.analyze(ebs_details)
            self.recommendations.extend(ebs_recs)
            print(f"[CostAnalyzer] EBS: {len(ebs_details)} volumes analyzed, {len(ebs_recs)} recommendations")
        
        # Lambda Checks
        lambda_details = self.inventory.get('lambda', {}).get('details', [])
        if lambda_details:
            self.recommendations.extend(LambdaCostChecks.analyze(lambda_details))
        
        # Network Checks (EIP + NAT)
        eip_details = self.inventory.get('eip', {}).get('details', [])
        nat_details = self.inventory.get('nat_gateway', {}).get('details', [])
        if eip_details or nat_details:
            self.recommendations.extend(NetworkCostChecks.analyze(eip_details, nat_details))
        
        # RDS Checks
        rds_details = self.inventory.get('rds', {}).get('details', [])
        if rds_details:
            self.recommendations.extend(RDSCostChecks.analyze(rds_details))
        
        # S3 Checks
        s3_details = self.inventory.get('s3', {}).get('details', [])
        if s3_details:
            self.recommendations.extend(S3CostChecks.analyze(s3_details))
        
        # ALB Checks
        alb_details = self.inventory.get('alb', {}).get('details', [])
        if alb_details:
            self.recommendations.extend(ALBCostChecks.analyze(alb_details))
        
        # ASG Checks
        asg_details = self.inventory.get('asg', {}).get('details', [])
        if asg_details:
            self.recommendations.extend(ASGCostChecks.analyze(asg_details))
        
        # DynamoDB Checks
        dynamodb_details = self.inventory.get('dynamodb', {}).get('details', [])
        if dynamodb_details:
            self.recommendations.extend(DynamoDBCostChecks.analyze(dynamodb_details))
        
        # CloudWatch Logs Checks
        logs_details = self.inventory.get('logs', {}).get('details', [])
        if logs_details:
            self.recommendations.extend(LogsCostChecks.analyze(logs_details))
        
        # Other Services Checks (SQS, SNS, Route53, CloudFront, CloudTrail, Backup)
        sqs_details = self.inventory.get('sqs', {}).get('details', [])
        sns_details = self.inventory.get('sns', {}).get('details', [])
        route53_details = self.inventory.get('route53', {}).get('details', [])
        cloudfront_details = self.inventory.get('cloudfront', {}).get('details', [])
        cloudtrail_details = self.inventory.get('cloudtrail', {}).get('details', [])
        backup_details = self.inventory.get('backup', {}).get('details', [])
        
        if any([sqs_details, sns_details, route53_details, cloudfront_details, cloudtrail_details, backup_details]):
            self.recommendations.extend(OtherServicesCostChecks.analyze(
                sqs_details, sns_details, route53_details, 
                cloudfront_details, cloudtrail_details, backup_details
            ))
        
        return self.recommendations
    
    def get_summary(self):
        """
        Get summary statistics of cost recommendations
        """
        if not self.recommendations:
            self.analyze()
        
        total_savings = sum(r.get('estimatedMonthlySavings', 0) for r in self.recommendations)
        
        # Group by service
        by_service = {}
        for rec in self.recommendations:
            service = rec['service']
            if service not in by_service:
                by_service[service] = {'count': 0, 'savings': 0}
            by_service[service]['count'] += 1
            by_service[service]['savings'] += rec.get('estimatedMonthlySavings', 0)
        
        # Group by severity
        by_severity = {}
        for rec in self.recommendations:
            severity = rec['severity']
            if severity not in by_severity:
                by_severity[severity] = 0
            by_severity[severity] += 1
        
        return {
            'totalRecommendations': len(self.recommendations),
            'totalPotentialMonthlySavings': round(total_savings, 2),
            'totalPotentialAnnualSavings': round(total_savings * 12, 2),
            'byService': by_service,
            'bySeverity': by_severity
        }
    
    def get_top_savings_opportunities(self, limit=10):
        """Get top N recommendations by potential savings"""
        if not self.recommendations:
            self.analyze()
        
        sorted_recs = sorted(
            self.recommendations,
            key=lambda x: x.get('estimatedMonthlySavings', 0),
            reverse=True
        )
        
        return sorted_recs[:limit]
