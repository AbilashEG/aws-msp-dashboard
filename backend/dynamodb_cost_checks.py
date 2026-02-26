"""
DynamoDB Cost Optimization Checks
Analyzes DynamoDB tables for cost savings
"""

class DynamoDBCostChecks:
    """DynamoDB-specific cost optimization checks"""
    
    @staticmethod
    def check_provisioned_underused(dynamodb_details):
        """Check for provisioned tables that are underused"""
        recommendations = []
        
        for table in dynamodb_details:
            if table.get('provisioned_underused'):
                recommendations.append({
                    'service': 'DynamoDB',
                    'checkId': 'dynamodb::provisioned_underused',
                    'resourceId': table['tableName'],
                    'region': table['region'],
                    'severity': 'Medium',
                    'category': 'cost_optimization',
                    'title': 'Underused Provisioned DynamoDB Table',
                    'description': f"Table {table['tableName']} using provisioned mode with low utilization",
                    'recommendation': 'Switch to On-Demand billing mode for unpredictable or low traffic',
                    'estimatedMonthlySavings': 20.0,
                    'potentialAction': 'switch_to_ondemand',
                    'details': {
                        'billingMode': table.get('billingMode'),
                        'readCapacity': table.get('readCapacityUnits'),
                        'writeCapacity': table.get('writeCapacityUnits')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def check_ondemand_high_traffic(dynamodb_details):
        """Check for on-demand tables with predictable high traffic"""
        recommendations = []
        
        for table in dynamodb_details:
            billing_mode = table.get('billingMode', '')
            item_count = table.get('itemCount', 0)
            
            # If on-demand with large item count, might benefit from provisioned
            if 'ON_DEMAND' in billing_mode and item_count > 100000:
                recommendations.append({
                    'service': 'DynamoDB',
                    'checkId': 'dynamodb::ondemand_high_traffic',
                    'resourceId': table['tableName'],
                    'region': table['region'],
                    'severity': 'Low',
                    'category': 'cost_optimization',
                    'title': 'On-Demand Table with High Traffic',
                    'description': f"Table {table['tableName']} using On-Demand with {item_count} items",
                    'recommendation': 'If traffic is predictable, switch to Provisioned mode with auto-scaling for cost savings',
                    'estimatedMonthlySavings': 30.0,
                    'potentialAction': 'switch_to_provisioned',
                    'details': {
                        'billingMode': billing_mode,
                        'itemCount': item_count,
                        'sizeBytes': table.get('sizeBytes')
                    }
                })
        
        return recommendations
    
    @staticmethod
    def analyze(dynamodb_details):
        """Run all DynamoDB cost checks"""
        recommendations = []
        
        recommendations.extend(DynamoDBCostChecks.check_provisioned_underused(dynamodb_details))
        recommendations.extend(DynamoDBCostChecks.check_ondemand_high_traffic(dynamodb_details))
        
        return recommendations
