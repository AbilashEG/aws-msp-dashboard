"""
Accurate Cost Calculator using AWS Pricing API
Gets real-time pricing data instead of hardcoded estimates
"""

import boto3
import json
from decimal import Decimal

class AccurateCostCalculator:
    """Get accurate AWS pricing using Pricing API"""
    
    def __init__(self, region='us-east-1'):
        self.pricing = boto3.client('pricing', region_name='us-east-1')  # Pricing API only in us-east-1
        self.cache = {}
    
    def get_ec2_hourly_cost(self, instance_type, region='us-east-1'):
        """Get actual EC2 hourly cost from Pricing API"""
        
        cache_key = f"ec2_{instance_type}_{region}"
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        try:
            # Map region codes
            region_map = {
                'us-east-1': 'US East (N. Virginia)',
                'us-west-2': 'US West (Oregon)',
                'ap-south-1': 'Asia Pacific (Mumbai)',
                'eu-west-1': 'EU (Ireland)',
                # Add more as needed
            }
            
            location = region_map.get(region, 'US East (N. Virginia)')
            
            response = self.pricing.get_products(
                ServiceCode='AmazonEC2',
                Filters=[
                    {'Type': 'TERM_MATCH', 'Field': 'instanceType', 'Value': instance_type},
                    {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': location},
                    {'Type': 'TERM_MATCH', 'Field': 'operatingSystem', 'Value': 'Linux'},
                    {'Type': 'TERM_MATCH', 'Field': 'tenancy', 'Value': 'Shared'},
                    {'Type': 'TERM_MATCH', 'Field': 'preInstalledSw', 'Value': 'NA'},
                    {'Type': 'TERM_MATCH', 'Field': 'capacitystatus', 'Value': 'Used'}
                ],
                MaxResults=1
            )
            
            if response['PriceList']:
                price_item = json.loads(response['PriceList'][0])
                on_demand = price_item['terms']['OnDemand']
                price_dimensions = list(on_demand.values())[0]['priceDimensions']
                hourly_cost = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                
                self.cache[cache_key] = hourly_cost
                return hourly_cost
            
        except Exception as e:
            print(f"[AccurateCost] Pricing API error for {instance_type}: {e}")
        
        # Fallback to estimate
        from cost_estimator import CostEstimator
        monthly = CostEstimator.estimate_ec2_monthly(instance_type)
        return monthly / 730  # Convert monthly to hourly
    
    def get_ec2_monthly_cost(self, instance_type, region='us-east-1'):
        """Get monthly EC2 cost (730 hours)"""
        hourly = self.get_ec2_hourly_cost(instance_type, region)
        return round(hourly * 730, 2)
    
    def get_ebs_monthly_cost(self, volume_type, size_gb, region='us-east-1'):
        """Get actual EBS monthly cost from Pricing API"""
        
        cache_key = f"ebs_{volume_type}_{region}"
        if cache_key in self.cache:
            cost_per_gb = self.cache[cache_key]
        else:
            try:
                region_map = {
                    'us-east-1': 'US East (N. Virginia)',
                    'us-west-2': 'US West (Oregon)',
                    'ap-south-1': 'Asia Pacific (Mumbai)',
                    'eu-west-1': 'EU (Ireland)',
                }
                
                location = region_map.get(region, 'US East (N. Virginia)')
                
                response = self.pricing.get_products(
                    ServiceCode='AmazonEC2',
                    Filters=[
                        {'Type': 'TERM_MATCH', 'Field': 'productFamily', 'Value': 'Storage'},
                        {'Type': 'TERM_MATCH', 'Field': 'volumeApiName', 'Value': volume_type},
                        {'Type': 'TERM_MATCH', 'Field': 'location', 'Value': location}
                    ],
                    MaxResults=1
                )
                
                if response['PriceList']:
                    price_item = json.loads(response['PriceList'][0])
                    on_demand = price_item['terms']['OnDemand']
                    price_dimensions = list(on_demand.values())[0]['priceDimensions']
                    cost_per_gb = float(list(price_dimensions.values())[0]['pricePerUnit']['USD'])
                    self.cache[cache_key] = cost_per_gb
                else:
                    # Fallback
                    from cost_estimator import CostEstimator
                    cost_per_gb = CostEstimator.EBS_GP3_COST
                    
            except Exception as e:
                print(f"[AccurateCost] EBS pricing error: {e}")
                from cost_estimator import CostEstimator
                cost_per_gb = CostEstimator.EBS_GP3_COST
        
        return round(size_gb * cost_per_gb, 2)
