"""
AI-Powered Cost Optimization using Amazon Bedrock Nova Pro
Analyzes billing data + resource utilization to generate intelligent recommendations
"""
import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class AICostOptimizer:
    """AI-powered cost optimization using Amazon Bedrock Nova Pro"""
    
    def __init__(self, bedrock_client):
        self.bedrock = bedrock_client
        self.model_id = "amazon.nova-pro-v1:0"
    
    def analyze(self, inventory: Dict, billing_data: Dict, account_id: str) -> Dict:
        """
        Analyze infrastructure and billing to generate AI-powered cost recommendations
        
        Args:
            inventory: Complete resource inventory from scan
            billing_data: Actual billing from Cost Explorer API
            account_id: AWS account ID being analyzed
            
        Returns:
            Dict with AI recommendations and summary
        """
        import time
        try:
            start_time = time.time()
            logger.info(f"Starting AI cost analysis for account {account_id}")
            
            # Build context from scan data and billing
            context_start = time.time()
            context = self._build_context(inventory, billing_data, account_id)
            context_time = time.time() - context_start
            logger.info(f"Context built in {context_time:.2f}s")
            
            # Create prompt for Bedrock Nova Pro
            prompt_start = time.time()
            prompt = self._build_prompt(context)
            prompt_time = time.time() - prompt_start
            logger.info(f"Prompt created in {prompt_time:.2f}s (length: {len(prompt)} chars)")
            
            # Call Bedrock Nova Pro
            bedrock_start = time.time()
            response = self._call_bedrock(prompt)
            bedrock_time = time.time() - bedrock_start
            logger.info(f"Bedrock API call completed in {bedrock_time:.2f}s")
            
            # Parse AI response into structured recommendations
            parse_start = time.time()
            recommendations = self._parse_response(response, context)
            parse_time = time.time() - parse_start
            logger.info(f"Response parsed in {parse_time:.2f}s")
            
            total_time = time.time() - start_time
            total_savings = sum(r.get('estimatedMonthlySavings', 0) for r in recommendations)
            logger.info(f"AI analysis complete: {len(recommendations)} recommendations generated in {total_time:.2f}s")
            logger.info(f"Total potential monthly savings: ${total_savings:.2f}")
            logger.info(f"Timing breakdown: Context={context_time:.2f}s, Prompt={prompt_time:.2f}s, Bedrock={bedrock_time:.2f}s, Parse={parse_time:.2f}s")
            
            return {
                'recommendations': recommendations,
                'summary': self._generate_summary(recommendations),
                'aiModel': self.model_id,
                'analysisTimestamp': billing_data.get('fetchedAt')
            }
            
        except Exception as e:
            logger.error(f"AI cost analysis failed: {e}")
            return {
                'recommendations': [],
                'summary': {'error': str(e)},
                'aiModel': self.model_id
            }
    
    def _build_context(self, inventory: Dict, billing_data: Dict, account_id: str) -> Dict:
        """Build structured context for AI analysis - ALL services from scan"""
        
        # Extract ALL service details from inventory
        ec2_details = inventory.get('ec2', {}).get('details', [])
        rds_details = inventory.get('rds', {}).get('details', [])
        lambda_details = inventory.get('lambda', {}).get('details', [])
        ebs_details = inventory.get('ebs', {}).get('details', [])
        s3_details = inventory.get('s3', {}).get('details', [])
        nat_details = inventory.get('nat_gateway', {}).get('details', [])
        alb_details = inventory.get('alb', {}).get('details', [])
        asg_details = inventory.get('asg', {}).get('details', [])
        dynamodb_details = inventory.get('dynamodb', {}).get('details', [])
        eip_details = inventory.get('eip', {}).get('details', [])
        logs_details = inventory.get('logs', {}).get('details', [])
        
        # Billing breakdown - ALL services from Cost Explorer
        service_costs = billing_data.get('serviceBreakdown', {})
        mtd_cost = billing_data.get('actualMonthToDate', 0)
        forecast = billing_data.get('forecastedMonthEnd', 0)
        
        context = {
            'accountId': account_id,
            'billing': {
                'monthToDate': mtd_cost,
                'forecastedMonthEnd': forecast,
                'serviceBreakdown': service_costs,  # ALL services from Cost Explorer
                'topServices': dict(sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10])
            },
            'resources': {
                'ec2': {
                    'total': len(ec2_details),
                    'idle': len([e for e in ec2_details if e.get('idle')]),
                    'running': len([e for e in ec2_details if e.get('state') == 'running']),
                    'instances': [
                        {
                            'id': e.get('instanceId'),
                            'name': e.get('instanceName', 'N/A'),
                            'type': e.get('instanceType'),
                            'platform': e.get('platform', 'Linux/UNIX'),
                            'region': e.get('region'),
                            'avgCpu': e.get('avgCpuPercent'),
                            'idle': e.get('idle', False),
                            'state': e.get('state')
                        }
                        for e in ec2_details if e.get('state') == 'running'  # Only running instances
                    ][:20]  # Top 20 for token efficiency
                },
                'rds': {
                    'total': len(rds_details),
                    'public': len([r for r in rds_details if r.get('publiclyAccessible')]),
                    'unencrypted': len([r for r in rds_details if not r.get('storageEncrypted')]),
                    'databases': [
                        {
                            'id': r.get('dbInstanceIdentifier'),
                            'engine': r.get('engine'),
                            'region': r.get('region'),
                            'multiAZ': r.get('multiAZ'),
                            'public': r.get('publiclyAccessible')
                        }
                        for r in rds_details
                    ][:10]
                },
                'lambda': {
                    'total': len(lambda_details),
                    'inefficient': len([l for l in lambda_details if l.get('inefficient')]),
                    'functions': [
                        {
                            'name': l.get('functionName'),
                            'memory': l.get('memoryMB'),
                            'region': l.get('region'),
                            'inefficient': l.get('inefficient', False)
                        }
                        for l in lambda_details
                    ][:10]
                },
                'ebs': {
                    'total': len(ebs_details),
                    'unattached': len([v for v in ebs_details if v.get('state') == 'available']),
                    'gp2': len([v for v in ebs_details if v.get('volumeType') == 'gp2']),
                    'totalSizeGB': sum(v.get('sizeGB', 0) for v in ebs_details)
                },
                's3': {
                    'total': len(s3_details),
                    'noLifecycle': len([b for b in s3_details if not b.get('hasLifecycleRule')]),
                    'publicRisk': len([b for b in s3_details if not b.get('publicAccessBlocked')])
                },
                'natGateway': {
                    'total': len(nat_details),
                    'regions': list(set(n.get('region') for n in nat_details))
                },
                'alb': {
                    'total': len(alb_details),
                    'httpOnly': len([a for a in alb_details if a.get('http_only')])
                },
                'asg': {
                    'total': len(asg_details),
                    'overMin': len([a for a in asg_details if a.get('over_min')])
                },
                'dynamodb': {
                    'total': len(dynamodb_details),
                    'provisionedUnderused': len([d for d in dynamodb_details if d.get('provisioned_underused')])
                },
                'eip': {
                    'total': len(eip_details),
                    'unassociated': len([e for e in eip_details if e.get('unassociated')])
                },
                'logs': {
                    'total': len(logs_details),
                    'neverExpire': len([l for l in logs_details if l.get('never_expire')])
                }
            },
            'summary': {
                'totalResourcesScanned': inventory.get('total_resources_discovered', 0),
                'regionsScanned': len(set(
                    r.get('region') for service in inventory.values() 
                    if isinstance(service, dict) and 'details' in service
                    for r in service['details'] if isinstance(r, dict) and 'region' in r
                ))
            }
        }
        
        return context
    
    def _build_prompt(self, context: Dict) -> str:
        """Build optimized prompt for Bedrock Nova Pro - ALL services"""
        
        billing = context['billing']
        resources = context['resources']
        summary = context['summary']
        
        prompt = f"""You are an AWS cost optimization expert. Analyze the following COMPLETE infrastructure and billing data to provide specific, actionable cost optimization recommendations.

BILLING OVERVIEW (from AWS Cost Explorer API):
- Account: {context['accountId']}
- Month-to-Date Spend: ${billing['monthToDate']:,.2f}
- Forecasted Month-End: ${billing['forecastedMonthEnd']:,.2f}
- Total Resources Scanned: {summary['totalResourcesScanned']}
- Regions Scanned: {summary['regionsScanned']}

TOP 10 SERVICES BY COST (Actual AWS Billing):
{json.dumps(billing['topServices'], indent=2)}

COMPLETE RESOURCE INVENTORY (All Regions):

EC2 Instances:
- Total: {resources['ec2']['total']}
- Running: {resources['ec2']['running']}
- Idle (CPU < 10%): {resources['ec2']['idle']}
- Running instances: {json.dumps(resources['ec2']['instances'][:5], indent=2)}

RDS Databases:
- Total: {resources['rds']['total']}
- Publicly Accessible: {resources['rds']['public']}
- Unencrypted: {resources['rds']['unencrypted']}
- Databases: {json.dumps(resources['rds']['databases'][:3], indent=2)}

Lambda Functions:
- Total: {resources['lambda']['total']}
- Inefficient (over-provisioned): {resources['lambda']['inefficient']}

EBS Volumes:
- Total: {resources['ebs']['total']}
- Unattached: {resources['ebs']['unattached']}
- GP2 (can upgrade to GP3): {resources['ebs']['gp2']}
- Total Size: {resources['ebs']['totalSizeGB']} GB

S3 Buckets:
- Total: {resources['s3']['total']}
- No Lifecycle Policy: {resources['s3']['noLifecycle']}
- Public Access Risk: {resources['s3']['publicRisk']}

NAT Gateways:
- Total: {resources['natGateway']['total']}
- Regions: {resources['natGateway']['regions']}

Application Load Balancers:
- Total: {resources['alb']['total']}
- HTTP Only (no HTTPS): {resources['alb']['httpOnly']}

Auto Scaling Groups:
- Total: {resources['asg']['total']}
- Over Minimum Capacity: {resources['asg']['overMin']}

DynamoDB Tables:
- Total: {resources['dynamodb']['total']}
- Provisioned Underused: {resources['dynamodb']['provisionedUnderused']}

Elastic IPs:
- Total: {resources['eip']['total']}
- Unassociated (wasted): {resources['eip']['unassociated']}

CloudWatch Log Groups:
- Total: {resources['logs']['total']}
- Never Expire (no retention): {resources['logs']['neverExpire']}

TASK:
Analyze the correlation between ACTUAL AWS BILLING (from Cost Explorer) and resource utilization across ALL services and regions. Provide 8-15 specific, high-impact cost optimization recommendations.

For each recommendation, provide:
1. Title (concise, actionable)
2. Resource ID or service name (specific)
3. Current monthly cost estimate (based on actual billing)
4. Optimized monthly cost estimate
5. Monthly savings
6. Confidence level (High/Medium/Low)
7. Detailed reasoning (correlate billing with utilization)
8. Implementation steps (3-5 specific actions)
9. Risk level (Low/Medium/High)

Focus on:
- Right-sizing over-provisioned resources (EC2, RDS, Lambda)
- Eliminating idle/unused resources (EC2, EBS, EIP, NAT)
- Storage optimization (GP2→GP3, S3 lifecycle, log retention)
- Scheduling non-production workloads
- Reserved Instances or Savings Plans for stable workloads
- DynamoDB on-demand vs provisioned
- Unassociated Elastic IPs ($3.60/month each)
- Unused NAT Gateways ($32/month each)
- S3 lifecycle policies for old data

IMPORTANT:
- Use ACTUAL billing data from serviceBreakdown to estimate costs
- Prioritize recommendations by potential savings
- Be specific with resource IDs when available
- Consider all regions scanned

OUTPUT FORMAT (JSON):
{{
  "recommendations": [
    {{
      "title": "string",
      "resourceId": "string",
      "service": "string",
      "region": "string",
      "currentMonthlyCost": number,
      "optimizedMonthlyCost": number,
      "monthlySavings": number,
      "confidence": "High|Medium|Low",
      "reasoning": "string (correlate with actual billing data)",
      "implementation": ["step1", "step2", "step3"],
      "risk": "Low|Medium|High"
    }}
  ]
}}

Provide ONLY the JSON output, no additional text."""

        return prompt
    
    def _call_bedrock(self, prompt: str) -> str:
        """Call Amazon Bedrock Nova Pro model"""
        try:
            logger.info(f"Calling Bedrock Nova Pro (model: {self.model_id})")
            
            # Prepare request body for Nova Pro
            request_body = {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ],
                "inferenceConfig": {
                    "temperature": 0.0,  # Zero temperature for fully deterministic, reproducible output
                    "maxTokens": 4096,
                    "topP": 1.0  # Set to 1.0 with temperature 0 for consistency
                }
            }
            
            # Invoke model
            response = self.bedrock.invoke_model(
                modelId=self.model_id,
                body=json.dumps(request_body),
                contentType="application/json",
                accept="application/json"
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            
            # Extract text from Nova Pro response format
            output_text = response_body['output']['message']['content'][0]['text']
            
            logger.info(f"Bedrock response received: {len(output_text)} characters")
            
            return output_text
            
        except Exception as e:
            logger.error(f"Bedrock API call failed: {e}")
            raise
    
    def _parse_response(self, response: str, context: Dict) -> List[Dict]:
        """Parse AI response into structured recommendations matching static format"""
        try:
            # Extract JSON from response (handle markdown code blocks)
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            response = response.strip()
            
            # Parse JSON
            data = json.loads(response)
            recommendations = data.get('recommendations', [])
            
            # Transform to match static recommendation format
            formatted_recs = []
            for rec in recommendations:
                formatted_rec = {
                    'service': rec.get('service', 'Unknown'),
                    'checkId': f"ai::{rec.get('service', 'unknown').lower()}::{rec.get('resourceId', 'general').replace('-', '_')}",
                    'resourceId': rec.get('resourceId', 'Multiple'),
                    'region': rec.get('region', 'global'),
                    'severity': self._map_confidence_to_severity(rec.get('confidence', 'Medium')),
                    'category': 'cost_optimization',
                    'title': rec.get('title', 'Cost Optimization'),
                    'description': rec.get('reasoning', ''),
                    'recommendation': ' | '.join(rec.get('implementation', [])),
                    'estimatedMonthlySavings': rec.get('monthlySavings', 0),
                    'potentialAction': 'ai_recommended',
                    'details': {
                        'currentMonthlyCost': rec.get('currentMonthlyCost', 0),
                        'optimizedMonthlyCost': rec.get('optimizedMonthlyCost', 0),
                        'confidence': rec.get('confidence', 'Medium'),
                        'risk': rec.get('risk', 'Low'),
                        'implementation': rec.get('implementation', []),
                        'aiGenerated': True,
                        'aiModel': self.model_id
                    }
                }
                formatted_recs.append(formatted_rec)
            
            return formatted_recs
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.error(f"Response: {response[:500]}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse AI response: {e}")
            return []
    
    def _map_confidence_to_severity(self, confidence: str) -> str:
        """Map AI confidence to severity level"""
        mapping = {
            'High': 'High',
            'Medium': 'Medium',
            'Low': 'Info'
        }
        return mapping.get(confidence, 'Medium')
    
    def _generate_summary(self, recommendations: List[Dict]) -> Dict:
        """Generate summary statistics from recommendations"""
        if not recommendations:
            return {
                'totalRecommendations': 0,
                'totalMonthlySavings': 0,
                'totalAnnualSavings': 0,
                'byConfidence': {},
                'byService': {}
            }
        
        total_savings = sum(r.get('monthlySavings', 0) for r in recommendations)
        
        # Group by confidence
        by_confidence = {}
        for rec in recommendations:
            conf = rec.get('confidence', 'Medium')
            by_confidence[conf] = by_confidence.get(conf, 0) + 1
        
        # Group by service
        by_service = {}
        for rec in recommendations:
            service = rec.get('service', 'Unknown')
            if service not in by_service:
                by_service[service] = {'count': 0, 'savings': 0}
            by_service[service]['count'] += 1
            by_service[service]['savings'] += rec.get('monthlySavings', 0)
        
        return {
            'totalRecommendations': len(recommendations),
            'totalMonthlySavings': round(total_savings, 2),
            'totalAnnualSavings': round(total_savings * 12, 2),
            'byConfidence': by_confidence,
            'byService': by_service
        }
