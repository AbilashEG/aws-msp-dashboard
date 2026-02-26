"""
Fetch ACTUAL AWS billing data from Cost Explorer API
This gives you the exact costs shown in AWS Console
"""
import boto3
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict

logger = logging.getLogger(__name__)


class ActualBillingFetcher:
    """Fetch actual AWS billing data using Cost Explorer API"""
    
    def __init__(self, session: boto3.Session):
        """
        Initialize with boto3 session
        Cost Explorer API is only available in us-east-1
        """
        self.ce_client = session.client('ce', region_name='us-east-1')
    
    def get_current_month_cost(self) -> Dict:
        """
        Get actual costs for current month from Cost Explorer
        Returns exact billing data shown in AWS Console
        """
        try:
            # Get current month date range
            now = datetime.now(timezone.utc)
            start_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            
            # Format dates for Cost Explorer API (YYYY-MM-DD)
            start_date = start_of_month.strftime('%Y-%m-%d')
            end_date = now.strftime('%Y-%m-%d')
            
            logger.info(f"Fetching actual billing from {start_date} to {end_date}")
            
            # Get total cost
            response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ]
            )
            
            # Parse response
            total_cost = 0.0
            service_breakdown = {}
            
            if response.get('ResultsByTime'):
                for result in response['ResultsByTime']:
                    for group in result.get('Groups', []):
                        service_name = group['Keys'][0]
                        cost = float(group['Metrics']['UnblendedCost']['Amount'])
                        
                        if cost > 0:
                            service_breakdown[service_name] = cost
                            total_cost += cost
            
            # Get forecasted month-end cost
            forecast_response = self.ce_client.get_cost_forecast(
                TimePeriod={
                    'Start': end_date,
                    'End': self._get_end_of_month().strftime('%Y-%m-%d')
                },
                Metric='UNBLENDED_COST',
                Granularity='MONTHLY'
            )
            
            forecasted_total = float(forecast_response['Total']['Amount'])
            
            logger.info(f"Actual billing fetched: ${total_cost:.2f} (MTD), Forecasted: ${forecasted_total:.2f}")
            
            return {
                'actualMonthToDate': round(total_cost, 2),
                'forecastedMonthEnd': round(forecasted_total, 2),
                'serviceBreakdown': {k: round(v, 2) for k, v in sorted(service_breakdown.items(), key=lambda x: x[1], reverse=True)},
                'currency': 'USD',
                'startDate': start_date,
                'endDate': end_date,
                'fetchedAt': datetime.now(timezone.utc).isoformat(),
                'source': 'AWS Cost Explorer API'
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch actual billing: {e}")
            return {
                'error': str(e),
                'actualMonthToDate': 0.0,
                'forecastedMonthEnd': 0.0,
                'serviceBreakdown': {},
                'note': 'Cost Explorer API access required. Enable in AWS Console or use IAM permissions.'
            }
    
    def get_last_month_cost(self) -> Dict:
        """Get actual costs for last complete month"""
        try:
            now = datetime.now(timezone.utc)
            
            # Last month date range
            first_of_this_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            last_month_end = first_of_this_month - timedelta(days=1)
            last_month_start = last_month_end.replace(day=1)
            
            start_date = last_month_start.strftime('%Y-%m-%d')
            end_date = first_of_this_month.strftime('%Y-%m-%d')
            
            response = self.ce_client.get_cost_and_usage(
                TimePeriod={
                    'Start': start_date,
                    'End': end_date
                },
                Granularity='MONTHLY',
                Metrics=['UnblendedCost'],
                GroupBy=[
                    {
                        'Type': 'DIMENSION',
                        'Key': 'SERVICE'
                    }
                ]
            )
            
            total_cost = 0.0
            service_breakdown = {}
            
            if response.get('ResultsByTime'):
                for result in response['ResultsByTime']:
                    for group in result.get('Groups', []):
                        service_name = group['Keys'][0]
                        cost = float(group['Metrics']['UnblendedCost']['Amount'])
                        
                        if cost > 0:
                            service_breakdown[service_name] = cost
                            total_cost += cost
            
            return {
                'totalCost': round(total_cost, 2),
                'serviceBreakdown': {k: round(v, 2) for k, v in sorted(service_breakdown.items(), key=lambda x: x[1], reverse=True)},
                'month': last_month_start.strftime('%B %Y'),
                'startDate': start_date,
                'endDate': end_date
            }
            
        except Exception as e:
            logger.error(f"Failed to fetch last month billing: {e}")
            return {'error': str(e), 'totalCost': 0.0}
    
    def _get_end_of_month(self) -> datetime:
        """Get last day of current month"""
        now = datetime.now(timezone.utc)
        next_month = now.replace(day=28) + timedelta(days=4)
        return next_month.replace(day=1) - timedelta(days=1)
