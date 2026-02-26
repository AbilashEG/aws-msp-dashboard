# AWS Dashboard Scoring Logic - Complete Explanation

## Overview
Your dashboard shows a **60% Global Health Score** for the account. This score is calculated based on 4 pillars, each starting at 100 and getting deducted when security/cost/governance issues are found.

---

## Global Health Score Formula

```python
global_score = max(0, min(100, int(
    pillar_scores['security']   * 0.35 +  # 35% weight
    pillar_scores['cost_proxy'] * 0.30 +  # 30% weight
    pillar_scores['health']     * 0.20 +  # 20% weight
    pillar_scores['governance'] * 0.15    # 15% weight
)))
```

**Example Calculation:**
If your account shows 60%, it might look like:
- Security: 50/100 (50 * 0.35 = 17.5)
- Cost: 60/100 (60 * 0.30 = 18.0)
- Health: 80/100 (80 * 0.20 = 16.0)
- Governance: 70/100 (70 * 0.15 = 10.5)
- **Total: 17.5 + 18 + 16 + 10.5 = 62%**

---

## Pillar Scores - Starting Values

All pillars start at **100 points** and get deducted when issues are found:

```python
self.pillar_scores = {
    'security':   100.0,  # Security posture
    'cost_proxy': 100.0,  # Cost optimization
    'health':     100.0,  # Resource health
    'governance': 100.0,  # Tagging & compliance
}
```

---

## Security Pillar Deductions (35% of Global Score)

### Critical Issues (-20 points each)
1. **Public RDS Database** (-20)
   - When: `publiclyAccessible = True`
   - Finding: "RDS {db_id} is publicly accessible"
   - Severity: High

2. **No Multi-Region CloudTrail** (-20)
   - When: No trail has `IsMultiRegionTrail = True`
   - Finding: "No multi-region CloudTrail trail"
   - Severity: High

3. **Public AMI** (-20)
   - When: AMI has `Public = True`
   - Finding: "Public AMI {ami_id}"
   - Severity: High

### High Issues (-15 points each)
4. **IMDSv1 Enabled on EC2** (-15)
   - When: Instance metadata `HttpTokens = 'optional'`
   - Finding: "IMDSv1 enabled on {instance_id}"
   - Severity: High

5. **Unencrypted RDS** (-15)
   - When: `StorageEncrypted = False`
   - Finding: "RDS {db_id} not encrypted"
   - Severity: High

6. **S3 Bucket Public Access Risk** (-15)
   - When: Block Public Access not fully enabled
   - Finding: "S3 bucket {name} incomplete Block Public Access"
   - Severity: High

7. **EKS Public Endpoint** (-15)
   - When: `endpointPublicAccess = True`
   - Finding: "EKS cluster {name} has public endpoint"
   - Severity: High

### Medium Issues (-10 to -12 points)
8. **ALB with HTTP Listener** (-12)
   - When: Load balancer has 'HTTP' protocol listener
   - Finding: "ALB {name} has HTTP listener"
   - Severity: High

9. **Unencrypted EBS Volume** (-10)
   - When: `Encrypted = False`
   - Finding: "Unencrypted EBS {volume_id}"
   - Severity: High

10. **CloudFront Allows HTTP** (-10)
    - When: `ViewerProtocolPolicy != 'redirect-to-https'`
    - Finding: "CloudFront {dist_id} allows HTTP"
    - Severity: High

### Low Issues (-5 points)
11. **Public Route53 Zone** (-5)
    - When: Hosted zone is not private
    - Finding: "Public hosted zone {zone_name}"
    - Severity: Medium

---

## Cost Pillar Deductions (30% of Global Score)

### Medium Issues (-8 points each)
1. **Idle EC2 Instance** (-8)
   - When: Average CPU < 10% over 14 days
   - Finding: "Idle EC2 {instance_id} – {avg_cpu}% avg CPU"
   - Severity: Medium

2. **Unattached EBS Volume** (-8)
   - When: Volume state = 'available' (not attached)
   - Finding: "Unattached EBS {volume_id}"
   - Severity: Medium

3. **Unassociated Elastic IP** (-8)
   - When: EIP has no `AssociationId`
   - Finding: "Unassociated EIP {public_ip}"
   - Severity: Medium

### Low Issues (-3 to -6 points)
4. **Inefficient Lambda Function** (-6)
   - When: Avg duration > 500ms AND memory ≤ 256MB
   - Finding: "Lambda {function_name} inefficient"
   - Severity: Medium

5. **ASG at MinSize** (-6)
   - When: Running instances ≤ MinSize (not scaling)
   - Finding: "ASG {name} at MinSize"
   - Severity: Medium

6. **Legacy gp2 EBS Volume** (-3)
   - When: Volume type = 'gp2' (should use gp3)
   - Finding: "Legacy gp2 volume {volume_id}"
   - Severity: Low

---

## Governance Pillar Deductions (15% of Global Score)

### Tag Violations (-8 points each)
1. **Missing Required Tags** (-8)
   - When: Resource missing any of: `Owner`, `Environment`, `Project`
   - Finding: "{resource_type} {resource_id} missing tags: {missing_tags}"
   - Severity: Medium
   - Checked on: EC2, EBS, S3, RDS, CloudFront

---

## Health Pillar (20% of Global Score)

Currently **no deductions** are implemented for the Health pillar. It remains at 100.

Potential future checks:
- Failed health checks
- Stopped instances
- Degraded services
- Backup failures

---

## Example: Why Your Account Shows 60%

Let's say your account has:
- **15 EC2 instances** with 3 having IMDSv1 enabled → -45 security points
- **2 RDS databases** both publicly accessible → -40 security points
- **5 idle EC2 instances** → -40 cost points
- **10 resources** missing tags → -80 governance points

**Calculation:**
```
Security:   100 - 45 - 40 = 15/100
Cost:       100 - 40 = 60/100
Health:     100 (no issues) = 100/100
Governance: 100 - 80 = 20/100

Global Score = (15 * 0.35) + (60 * 0.30) + (100 * 0.20) + (20 * 0.15)
             = 5.25 + 18 + 20 + 3
             = 46.25% ≈ 46%
```

---

## How to Improve Your Score

### To Improve Security (35% impact):
1. ✅ Disable IMDSv1 on all EC2 instances (+15 per instance)
2. ✅ Make RDS databases private (+20 per database)
3. ✅ Enable S3 Block Public Access (+15 per bucket)
4. ✅ Encrypt all EBS volumes (+10 per volume)
5. ✅ Enable multi-region CloudTrail (+20)

### To Improve Cost (30% impact):
1. ✅ Stop or terminate idle EC2 instances (+8 per instance)
2. ✅ Delete unattached EBS volumes (+8 per volume)
3. ✅ Release unassociated Elastic IPs (+8 per IP)
4. ✅ Optimize Lambda memory settings (+6 per function)
5. ✅ Migrate gp2 to gp3 volumes (+3 per volume)

### To Improve Governance (15% impact):
1. ✅ Add required tags (Owner, Environment, Project) to all resources (+8 per resource)

---

## Viewing Detailed Findings

In your dashboard:
1. Go to **Findings** tab
2. See all issues sorted by severity (Critical → High → Medium → Low)
3. Each finding shows:
   - Severity level
   - Title (what's wrong)
   - Category (security/cost/governance)
   - Resource ID
   - Region

---

## Score Ranges

- **90-100%**: Excellent - Very few issues
- **70-89%**: Good - Some optimization needed
- **50-69%**: Fair - Multiple issues to address
- **30-49%**: Poor - Significant security/cost risks
- **0-29%**: Critical - Immediate action required

Your **60%** falls in the **Fair** range, meaning there are several issues that should be addressed, particularly in security and governance.
