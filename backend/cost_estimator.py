"""
Cost Estimator - Simple cost calculations without Pricing API
Provides approximate monthly costs for AWS resources
"""

class CostEstimator:
    """Estimate AWS resource costs without using Pricing API"""
    
    # EC2 On-Demand Pricing (US East 1, Linux, approximate monthly cost for 730 hours)
    EC2_COSTS = {
        # T2 Family
        't2.nano': 4.25, 't2.micro': 8.5, 't2.small': 17, 't2.medium': 34, 't2.large': 68, 't2.xlarge': 135, 't2.2xlarge': 270,
        
        # T3 Family
        't3.nano': 3.8, 't3.micro': 7.5, 't3.small': 15, 't3.medium': 30, 't3.large': 60, 't3.xlarge': 120, 't3.2xlarge': 240,
        
        # M5 Family
        'm5.large': 70, 'm5.xlarge': 140, 'm5.2xlarge': 280, 'm5.4xlarge': 560, 'm5.8xlarge': 1120,
        
        # C5 Family
        'c5.large': 62, 'c5.xlarge': 124, 'c5.2xlarge': 248, 'c5.4xlarge': 496,
        
        # R5 Family
        'r5.large': 91, 'r5.xlarge': 182, 'r5.2xlarge': 365, 'r5.4xlarge': 730,
    }
    
    # Storage Costs (per GB per month)
    EBS_GP3_COST = 0.08
    EBS_GP2_COST = 0.10
    EBS_IO1_COST = 0.125
    EBS_IO2_COST = 0.125
    EBS_ST1_COST = 0.045
    EBS_SC1_COST = 0.015
    
    # Network Costs
    EIP_UNASSOCIATED_COST = 3.65  # per month
    NAT_GATEWAY_BASE_COST = 32.85  # per month (plus data transfer)
    
    # RDS Costs (approximate, varies by engine)
    RDS_MULTIPLIER = 1.5  # RDS typically 1.5x EC2 cost
    
    @staticmethod
    def estimate_ec2_monthly(instance_type: str) -> float:
        """Estimate monthly EC2 cost"""
        return CostEstimator.EC2_COSTS.get(instance_type, 50.0)
    
    @staticmethod
    def estimate_ebs_monthly(volume_type: str, size_gb: int) -> float:
        """Estimate monthly EBS cost"""
        cost_per_gb = {
            'gp3': CostEstimator.EBS_GP3_COST,
            'gp2': CostEstimator.EBS_GP2_COST,
            'io1': CostEstimator.EBS_IO1_COST,
            'io2': CostEstimator.EBS_IO2_COST,
            'st1': CostEstimator.EBS_ST1_COST,
            'sc1': CostEstimator.EBS_SC1_COST,
        }.get(volume_type, 0.10)
        
        return size_gb * cost_per_gb
    
    @staticmethod
    def estimate_gp2_to_gp3_savings(size_gb: int) -> float:
        """Calculate savings from migrating gp2 to gp3"""
        gp2_cost = size_gb * CostEstimator.EBS_GP2_COST
        gp3_cost = size_gb * CostEstimator.EBS_GP3_COST
        return gp2_cost - gp3_cost
    
    @staticmethod
    def estimate_rds_monthly(instance_type: str) -> float:
        """Estimate monthly RDS cost (approximate)"""
        ec2_cost = CostEstimator.estimate_ec2_monthly(instance_type)
        return ec2_cost * CostEstimator.RDS_MULTIPLIER
    
    @staticmethod
    def estimate_lambda_monthly(memory_mb: int, avg_duration_ms: float, invocations_per_month: int = 1000000) -> float:
        """Estimate monthly Lambda cost"""
        # Lambda pricing: $0.0000166667 per GB-second
        gb_seconds = (memory_mb / 1024) * (avg_duration_ms / 1000) * invocations_per_month
        compute_cost = gb_seconds * 0.0000166667
        
        # Request cost: $0.20 per 1M requests
        request_cost = (invocations_per_month / 1000000) * 0.20
        
        return compute_cost + request_cost
