# Why AI Savings Change Between Scans ($2500 → $3500)

## The Problem: Non-Deterministic AI

Your AI recommendations are changing between scans:
- **First scan**: $2500 monthly savings
- **Second scan**: $3500 monthly savings
- **Same infrastructure, same billing data**

## Root Cause: Temperature Setting

```python
"inferenceConfig": {
    "temperature": 0.3,  # ← This allows randomness!
    "maxTokens": 4096,
    "topP": 0.9
}
```

### What is Temperature?

**Temperature** controls AI randomness:
- **0.0** = Completely deterministic (same input → same output)
- **0.3** = Slightly random (same input → similar but different output)
- **1.0** = Very random (same input → very different output)

### Why 0.3 Causes Variation:

With temperature 0.3, the AI can:
1. **Estimate different costs** for the same resource
   - Idle EC2: $700 savings (first scan) vs $900 savings (second scan)
   
2. **Group resources differently**
   - First scan: 4 separate recommendations
   - Second scan: Combined into 2 recommendations

3. **Prioritize different optimizations**
   - First scan: Focus on EC2 + S3
   - Second scan: Focus on EC2 + Reserved Instances

4. **Calculate savings differently**
   - First scan: Conservative estimates
   - Second scan: Aggressive estimates

## Example: Same Data, Different Results

### Scan 1 (Total: $2500):
```
1. Terminate 4 idle EC2 → $700
2. S3 lifecycle → $300
3. Unattached EBS → $200
4. NAT Gateway → $80
5. Reserved Instances → $400
6. Lambda right-sizing → $20
... (8 recommendations)
```

### Scan 2 (Total: $3500):
```
1. Terminate 4 idle EC2 → $900  ← Higher estimate!
2. S3 lifecycle → $500  ← Higher estimate!
3. Unattached EBS → $250  ← Higher estimate!
4. NAT Gateway → $100  ← Higher estimate!
5. Reserved Instances → $600  ← Higher estimate!
6. Lambda right-sizing → $30  ← Higher estimate!
... (8 recommendations)
```

**Same resources, different cost estimates!**

## Why This Happens:

### 1. **AI Estimation Variance**
The AI estimates costs based on:
- Billing data patterns
- Resource utilization
- Industry benchmarks
- **Random sampling** (due to temperature > 0)

With temperature 0.3, the AI might:
- Estimate idle EC2 cost as $150-200/month (varies)
- Estimate S3 storage cost as $30-50/month (varies)
- Round numbers differently ($709 vs $700)

### 2. **Recommendation Grouping**
The AI might group resources differently:
- **Scan 1**: "Terminate i-123" ($200) + "Terminate i-456" ($150) = $350
- **Scan 2**: "Terminate idle instances i-123, i-456" ($400) = $400

### 3. **Prioritization Changes**
With limited output (4096 tokens), AI might:
- **Scan 1**: Include 8 smaller recommendations
- **Scan 2**: Include 10 recommendations with different priorities

## Solution: Lower Temperature to 0.0

### Current (Non-Deterministic):
```python
"temperature": 0.3  # Allows 20-40% variance in savings
```

### Fixed (Deterministic):
```python
"temperature": 0.0  # Same input → same output
```

## Trade-offs:

### Temperature 0.3 (Current):
✅ More creative recommendations
✅ Explores different optimization strategies
❌ **Inconsistent savings estimates**
❌ **Confusing for users** ($2500 → $3500)
❌ Hard to track improvements

### Temperature 0.0 (Recommended):
✅ **Consistent savings estimates**
✅ **Reproducible results**
✅ Easy to track improvements
✅ Builds user trust
❌ Less creative (but still accurate)

## Expected Behavior After Fix:

### Before (Temperature 0.3):
```
Scan 1: $2500 savings
Scan 2: $3500 savings  ← 40% variance!
Scan 3: $2800 savings
Scan 4: $3200 savings
```

### After (Temperature 0.0):
```
Scan 1: $3000 savings
Scan 2: $3000 savings  ← Consistent!
Scan 3: $3000 savings
Scan 4: $3000 savings

(Only changes if infrastructure or billing changes)
```

## When Savings SHOULD Change:

✅ **Valid reasons for different savings:**
1. **Infrastructure changed** (added/removed resources)
2. **Billing data changed** (different month-to-date cost)
3. **Utilization changed** (EC2 no longer idle)
4. **You implemented recommendations** (fewer opportunities)

❌ **Invalid reasons (current behavior):**
1. Same infrastructure, same billing → different savings
2. AI randomness causing variance
3. Different cost estimates for same resources

## Recommendation:

**Change temperature from 0.3 to 0.0** for consistent, reproducible results.

Users expect:
- Same scan → Same recommendations → Same savings
- Only change when infrastructure/billing changes
- Predictable, trustworthy AI analysis
