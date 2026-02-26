"""
AI-Powered Security & Compliance Analyzer using Amazon Bedrock Nova Pro
Analyzes complete infrastructure across all regions + billing data to identify security risks
"""
import json
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class AISecurityAnalyzer:
    """AI-powered security and compliance analyzer using Amazon Bedrock Nova Pro"""
    
    def __init__(self, bedrock_client):
        self.bedrock = bedrock_client
        self.model_id = "amazon.nova-pro-v1:0"
    
    def analyze(self, inventory: Dict, billing_data: Dict, account_id: str, regions_scanned: List[str]) -> Dict:
        """
        Analyze infrastructure for security risks and compliance violations
        
        Args:
            inventory: Complete resource inventory from scan (all regions)
            billing_data: Actual billing from Cost Explorer API
            account_id: AWS account ID being analyzed
            regions_scanned: List of AWS regions scanned
            
        Returns:
            Dict with AI security findings and compliance summary
        """
        import time
        try:
            start_time = time.time()
            logger.info(f"Starting AI security analysis for account {account_id}")
            
            # Build security context
            context_start = time.time()
            context = self._build_security_context(inventory, billing_data, account_id, regions_scanned)
            context_time = time.time() - context_start
            logger.info(f"Security context built in {context_time:.2f}s")
            
            # Create prompt for Bedrock Nova Pro
            prompt_start = time.time()
            prompt = self._build_security_prompt(context)
            prompt_time = time.time() - prompt_start
            logger.info(f"Security prompt created in {prompt_time:.2f}s (length: {len(prompt)} chars)")
            
            # Call Bedrock Nova Pro
            bedrock_start = time.time()
            response = self._call_bedrock(prompt)
            bedrock_time = time.time() - bedrock_start
            logger.info(f"Bedrock security analysis completed in {bedrock_time:.2f}s")
            
            # Parse AI response into security findings
            parse_start = time.time()
            findings = self._parse_security_findings(response, context)
            parse_time = time.time() - parse_start
            logger.info(f"Security findings parsed in {parse_time:.2f}s")
            
            total_time = time.time() - start_time
            critical_high = len([f for f in findings if f.get('severity') in ('Critical', 'High')])
            logger.info(f"AI security analysis complete: {len(findings)} findings ({critical_high} Critical/High) in {total_time:.2f}s")
            
            return {
                'findings': findings,
                'summary': self._generate_security_summary(findings),
                'aiModel': self.model_id,
                'analysisTimestamp': billing_data.get('fetchedAt'),
                'regionsScanned': regions_scanned,
                'accountId': account_id
            }
            
        except Exception as e:
            logger.error(f"AI security analysis failed: {e}")
            return {
                'findings': [],
                'summary': {'error': str(e)},
                'aiModel': self.model_id
            }
    
    def _build_security_context(self, inventory: Dict, billing_data: Dict, account_id: str, regions_scanned: List[str]) -> Dict:
        """Build comprehensive security context from all scanned data"""
        
        # Extract resource details
        ec2_details = inventory.get('ec2', {}).get('details', [])
        rds_details = inventory.get('rds', {}).get('details', [])
        s3_details = inventory.get('s3', {}).get('details', [])
        ebs_details = inventory.get('ebs', {}).get('details', [])
        nat_details = inventory.get('nat_gateway', {}).get('details', [])
        eip_details = inventory.get('eip', {}).get('details', [])
        
        # Billing data
        service_costs = billing_data.get('serviceBreakdown', {})
        mtd_cost = billing_data.get('actualMonthToDate', 0)
        
        context = {
            'accountId': account_id,
            'regionsScanned': regions_scanned,
            'totalRegions': len(regions_scanned),
            'billing': {
                'monthToDate': mtd_cost,
                'forecastedMonthEnd': billing_data.get('forecastedMonthEnd', 0),
                'topServices': dict(sorted(service_costs.items(), key=lambda x: x[1], reverse=True)[:10])
            },
            'security': {
                'ec2': {
                    'total': len(ec2_details),
                    'publicIp': len([e for e in ec2_details if e.get('publicIp')]),
                    'imdsv1': len([e for e in ec2_details if e.get('imds_v1')]),
                    'instances': [
                        {
                            'id': e.get('instanceId'),
                            'name': e.get('instanceName', 'N/A'),
                            'region': e.get('region'),
                            'publicIp': e.get('publicIp'),
                            'imdsv1': e.get('imds_v1', False),
                            'state': e.get('state')
                        }
                        for e in ec2_details
                    ][:20]
                },
                'rds': {
                    'total': len(rds_details),
                    'public': len([r for r in rds_details if r.get('publiclyAccessible')]),
                    'unencrypted': len([r for r in rds_details if not r.get('storageEncrypted')]),
                    'noMultiAZ': len([r for r in rds_details if not r.get('multiAZ')]),
                    'databases': [
                        {
                            'id': r.get('dbInstanceIdentifier'),
                            'engine': r.get('engine'),
                            'region': r.get('region'),
                            'public': r.get('publiclyAccessible', False),
                            'encrypted': r.get('storageEncrypted', False),
                            'multiAZ': r.get('multiAZ', False)
                        }
                        for r in rds_details
                    ]
                },
                's3': {
                    'total': len(s3_details),
                    'publicRisk': len([b for b in s3_details if not b.get('publicAccessBlocked')]),
                    'noLifecycle': len([b for b in s3_details if not b.get('hasLifecycleRule')]),
                    'buckets': [
                        {
                            'name': b.get('bucketName'),
                            'publicBlocked': b.get('publicAccessBlocked', False),
                            'lifecycle': b.get('hasLifecycleRule', False)
                        }
                        for b in s3_details
                    ][:10]
                },
                'ebs': {
                    'total': len(ebs_details),
                    'unencrypted': len([v for v in ebs_details if not v.get('encrypted')]),
                    'unattached': len([v for v in ebs_details if v.get('state') == 'available'])
                },
                'network': {
                    'natGateways': len(nat_details),
                    'unassociatedEIPs': len([e for e in eip_details if e.get('unassociated')])
                }
            },
            'totalResources': inventory.get('total_resources_discovered', 0)
        }
        
        return context
    
    def _build_security_prompt(self, context: Dict) -> str:
        """Build comprehensive security analysis prompt for Bedrock Nova Pro"""
        
        billing = context['billing']
        security = context['security']
        
        prompt = f"""You are an AWS security and compliance expert. Analyze the following COMPLETE infrastructure data across ALL regions to identify security risks, misconfigurations, and compliance violations.

ACCOUNT OVERVIEW:
- Account ID: {context['accountId']}
- Regions Scanned: {context['totalRegions']} regions ({', '.join(context['regionsScanned'][:5])}...)
- Total Resources: {context['totalResources']}
- Monthly Spend: ${billing['monthToDate']:,.2f}

BILLING CONTEXT (Correlate with Security):
Top Services by Cost:
{json.dumps(billing['topServices'], indent=2)}

SECURITY INVENTORY (All Regions):

EC2 INSTANCES:
- Total: {security['ec2']['total']}
- With Public IP: {security['ec2']['publicIp']} ⚠️
- Using IMDSv1: {security['ec2']['imdsv1']} ⚠️
- Sample instances: {json.dumps(security['ec2']['instances'][:5], indent=2)}

RDS DATABASES:
- Total: {security['rds']['total']}
- Publicly Accessible: {security['rds']['public']} 🚨
- Unencrypted Storage: {security['rds']['unencrypted']} 🚨
- No Multi-AZ: {security['rds']['noMultiAZ']} ⚠️
- Databases: {json.dumps(security['rds']['databases'], indent=2)}

S3 BUCKETS:
- Total: {security['s3']['total']}
- Public Access Risk: {security['s3']['publicRisk']} 🚨
- No Lifecycle Policy: {security['s3']['noLifecycle']} ⚠️
- Sample buckets: {json.dumps(security['s3']['buckets'][:5], indent=2)}

EBS VOLUMES:
- Total: {security['ebs']['total']}
- Unencrypted: {security['ebs']['unencrypted']} 🚨
- Unattached (wasted): {security['ebs']['unattached']} ⚠️

NETWORK SECURITY:
- NAT Gateways: {security['network']['natGateways']}
- Unassociated Elastic IPs: {security['network']['unassociatedEIPs']} ⚠️

TASK:
Perform a BULLETPROOF security analysis and identify ALL security risks, misconfigurations, and compliance violations. Correlate billing data with security posture to identify potential data exfiltration risks or cost anomalies.

For each finding, provide:
1. Severity (Critical/High/Medium/Low/Info)
2. Title (concise, actionable)
3. Resource ID or type (specific)
4. Region (or "All" if global)
5. Category (encryption, network, access_control, logging, compliance, data_protection)
6. Risk description (detailed explanation of the security risk)
7. Compliance frameworks violated (CIS AWS Foundations, PCI-DSS, HIPAA, GDPR, SOC2)
8. Potential impact (data breach, unauthorized access, compliance violation, etc.)
9. Remediation steps (3-5 specific, actionable steps)
10. Risk level (Critical/High/Medium/Low)

FOCUS AREAS:
1. **Data Protection**:
   - Unencrypted databases (RDS, EBS)
   - Public S3 buckets
   - Missing encryption at rest

2. **Network Security**:
   - Publicly accessible databases
   - EC2 instances with public IPs
   - Overly permissive security groups (0.0.0.0/0)
   - Unassociated Elastic IPs

3. **Access Control**:
   - IMDSv1 usage (metadata service vulnerability)
   - Public access to sensitive resources
   - Missing MFA

4. **Compliance**:
   - CIS AWS Foundations Benchmark violations
   - PCI-DSS requirements (encryption, network segmentation)
   - HIPAA controls (encryption, audit logging)
   - GDPR data protection requirements

5. **Operational Security**:
   - No Multi-AZ for production databases
   - Missing backup coverage
   - No lifecycle policies (data retention)

6. **Cost-Security Correlation**:
   - High billing + public resources = potential data exfiltration
   - Unused resources with security risks
   - Cost anomalies indicating security incidents

COMPLIANCE FRAMEWORKS:
- CIS AWS Foundations Benchmark v1.4
- PCI-DSS v3.2.1
- HIPAA Security Rule
- GDPR Article 32 (Security of Processing)
- SOC 2 Type II
- NIST Cybersecurity Framework

OUTPUT FORMAT (JSON):
{{
  "findings": [
    {{
      "severity": "Critical|High|Medium|Low|Info",
      "title": "string",
      "resourceId": "string",
      "resourceType": "EC2|RDS|S3|EBS|VPC|IAM|etc",
      "region": "string",
      "category": "encryption|network|access_control|logging|compliance|data_protection",
      "riskDescription": "string (detailed explanation)",
      "complianceFrameworks": ["CIS 2.3.1", "PCI-DSS 3.4", "HIPAA 164.312(a)(2)(iv)"],
      "potentialImpact": "string (data breach, unauthorized access, etc.)",
      "remediation": ["step1", "step2", "step3"],
      "riskLevel": "Critical|High|Medium|Low",
      "estimatedRemediationTime": "string (e.g., '15 minutes', '1 hour')"
    }}
  ]
}}

IMPORTANT:
- Prioritize findings by severity (Critical > High > Medium > Low)
- Be specific with resource IDs when available
- Correlate billing data with security risks
- Provide actionable, step-by-step remediation
- Map findings to compliance frameworks
- Consider all {context['totalRegions']} scanned regions

Provide ONLY the JSON output, no additional text."""

        return prompt
    
    def _call_bedrock(self, prompt: str) -> str:
        """Call Amazon Bedrock Nova Pro model for security analysis"""
        try:
            logger.info(f"Calling Bedrock Nova Pro for security analysis (model: {self.model_id})")
            
            # Prepare request body for Nova Pro
            request_body = {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ],
                "inferenceConfig": {
                    "temperature": 0.0,  # Deterministic for consistent security findings
                    "maxTokens": 8192,   # More tokens for comprehensive security analysis
                    "topP": 1.0
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
            output_text = response_body['output']['message']['content'][0]['text']
            
            logger.info(f"Bedrock security analysis response received: {len(output_text)} characters")
            
            return output_text
            
        except Exception as e:
            logger.error(f"Bedrock API call failed: {e}")
            raise
    
    def _parse_security_findings(self, response: str, context: Dict) -> List[Dict]:
        """Parse AI response into structured security findings"""
        try:
            # Extract JSON from response
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
            findings = data.get('findings', [])
            
            # Format findings
            formatted_findings = []
            for finding in findings:
                formatted_finding = {
                    'severity': finding.get('severity', 'Medium'),
                    'title': finding.get('title', 'Security Finding'),
                    'resourceId': finding.get('resourceId', 'N/A'),
                    'resourceType': finding.get('resourceType', 'Unknown'),
                    'region': finding.get('region', 'global'),
                    'category': finding.get('category', 'security'),
                    'description': finding.get('riskDescription', ''),
                    'complianceFrameworks': finding.get('complianceFrameworks', []),
                    'potentialImpact': finding.get('potentialImpact', ''),
                    'remediation': ' | '.join(finding.get('remediation', [])),
                    'riskLevel': finding.get('riskLevel', 'Medium'),
                    'estimatedRemediationTime': finding.get('estimatedRemediationTime', 'Unknown'),
                    'aiGenerated': True,
                    'aiModel': self.model_id
                }
                formatted_findings.append(formatted_finding)
            
            return formatted_findings
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI security response as JSON: {e}")
            logger.error(f"Response: {response[:500]}")
            return []
        except Exception as e:
            logger.error(f"Failed to parse AI security response: {e}")
            return []
    
    def _generate_security_summary(self, findings: List[Dict]) -> Dict:
        """Generate summary statistics from security findings"""
        if not findings:
            return {
                'totalFindings': 0,
                'criticalCount': 0,
                'highCount': 0,
                'mediumCount': 0,
                'lowCount': 0,
                'byCategory': {},
                'byCompliance': {}
            }
        
        # Count by severity
        severity_counts = {
            'Critical': len([f for f in findings if f.get('severity') == 'Critical']),
            'High': len([f for f in findings if f.get('severity') == 'High']),
            'Medium': len([f for f in findings if f.get('severity') == 'Medium']),
            'Low': len([f for f in findings if f.get('severity') == 'Low']),
            'Info': len([f for f in findings if f.get('severity') == 'Info'])
        }
        
        # Group by category
        by_category = {}
        for finding in findings:
            category = finding.get('category', 'other')
            by_category[category] = by_category.get(category, 0) + 1
        
        # Group by compliance framework
        by_compliance = {}
        for finding in findings:
            frameworks = finding.get('complianceFrameworks', [])
            for framework in frameworks:
                by_compliance[framework] = by_compliance.get(framework, 0) + 1
        
        return {
            'totalFindings': len(findings),
            'criticalCount': severity_counts['Critical'],
            'highCount': severity_counts['High'],
            'mediumCount': severity_counts['Medium'],
            'lowCount': severity_counts['Low'],
            'infoCount': severity_counts.get('Info', 0),
            'bySeverity': severity_counts,
            'byCategory': by_category,
            'byCompliance': by_compliance
        }
