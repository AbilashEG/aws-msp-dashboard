# AWS Multi-Account MSP Monitoring Dashboard

A comprehensive AWS monitoring solution for Managed Service Providers (MSPs) to monitor multiple customer accounts from a centralized hub.

## 🚀 Features

### Current Features
- **Multi-Account Monitoring**: Monitor 20+ AWS services across multiple customer accounts
- **Centralized Dashboard**: React-based UI with real-time data visualization
- **Security Analysis**: AI-powered security scanning using Amazon Bedrock Nova Pro
- **Cost Optimization**: Automated cost analysis and recommendations
- **Backup Coverage**: Track backup status across EC2, RDS, and EBS
- **Health Scoring**: Comprehensive health metrics (Security, Cost, Performance, Reliability)
- **Cross-Account Access**: Secure AssumeRole-based access with ReadOnly permissions

### Monitored AWS Services (20+)
- **Compute**: EC2, Lambda, Auto Scaling Groups
- **Storage**: EBS, S3, Backup Vaults
- **Database**: RDS, DynamoDB
- **Network**: VPC, Subnets, NAT Gateways, Elastic IPs, ALB
- **CDN & DNS**: CloudFront, Route 53
- **Security**: CloudTrail, Security Groups
- **Messaging**: SQS, SNS
- **Container**: ECS, ECR

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HUB ACCOUNT (325809079703)               │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  React Dashboard (Frontend)                          │  │
│  │  • Account Groups Management                         │  │
│  │  • Resource Inventory Visualization                  │  │
│  │  • Security & Cost Analytics                         │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                         │
│                   ▼                                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  Flask Backend (Python)                              │  │
│  │  • MSPMonitoringScanner                             │  │
│  │  • AI Security Analyzer (Bedrock Nova Pro)          │  │
│  │  • Cost Optimizer                                    │  │
│  │  • Backup Coverage Analyzer                          │  │
│  └────────────────┬─────────────────────────────────────┘  │
│                   │                                         │
│                   ▼                                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  DynamoDB: L1-Account-Groups                         │  │
│  │  • Account group configurations                      │  │
│  │  • Customer account mappings                         │  │
│  └──────────────────────────────────────────────────────┘  │
└───────────────────────┼─────────────────────────────────────┘
                        │ (AssumeRole ReadOnly)
                        ▼
        ┌───────────────────────────────────────┐
        │  Customer Accounts (5+ accounts)      │
        │  • ReadOnly-Cross-Account Role        │
        │  • Multi-region scanning (10 regions) │
        │  • Parallel processing                │
        └───────────────────────────────────────┘
```

## 🛠️ Technology Stack

### Backend
- **Python 3.11+**
- **Flask** - REST API
- **Boto3** - AWS SDK
- **Amazon Bedrock** - AI-powered analysis (Nova Pro)
- **DynamoDB** - Account configuration storage

### Frontend
- **React 18**
- **TypeScript**
- **Material-UI (MUI)**
- **Recharts** - Data visualization
- **Axios** - HTTP client

## 📋 Prerequisites

- Python 3.11 or higher
- Node.js 18+ and npm
- AWS Account with appropriate permissions
- AWS CLI configured

## 🔧 Installation

### Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Flask server
python app.py
```

Backend will run on `http://localhost:5000`

### Frontend Setup

```bash
# Navigate to frontend directory
cd frontend

# Install dependencies
npm install

# Start development server
npm start
```

Frontend will run on `http://localhost:3000`

## ⚙️ Configuration

### 1. DynamoDB Table Setup

Create a DynamoDB table named `L1-Account-Groups`:

```json
{
  "TableName": "L1-Account-Groups",
  "KeySchema": [
    { "AttributeName": "groupId", "KeyType": "HASH" }
  ],
  "AttributeDefinitions": [
    { "AttributeName": "groupId", "AttributeType": "S" }
  ],
  "BillingMode": "PAY_PER_REQUEST"
}
```

### 2. Customer Account Configuration

Add account groups to DynamoDB:

```json
{
  "groupId": "group-001",
  "groupName": "Production Accounts",
  "accounts": [
    {
      "accountId": "123456789012",
      "accountName": "Customer A - Production",
      "roleArn": "arn:aws:iam::123456789012:role/ReadOnly-Cross-Account"
    }
  ],
  "regions": ["us-east-1", "us-west-2", "eu-west-1"]
}
```

### 3. IAM Role Setup (Customer Accounts)

Create `ReadOnly-Cross-Account` role in each customer account:

**Trust Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::325809079703:root"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "msp-monitoring-2026"
        }
      }
    }
  ]
}
```

**Permissions Policy:**
- Attach AWS managed policy: `ReadOnlyAccess`
- Or use custom policy with specific read permissions

## 📊 Usage

### 1. Access Dashboard
Navigate to `http://localhost:3000`

### 2. Select Account Group
Choose an account group from the dropdown

### 3. Scan Accounts
Click "Scan Accounts" to start inventory collection

### 4. View Results
- **Overview Tab**: Health scores and summary metrics
- **Compute Tab**: EC2, Lambda, ASG details
- **Storage Tab**: EBS, S3, Backup coverage
- **Database Tab**: RDS, DynamoDB details
- **Network Tab**: VPC, Subnets, NAT Gateways, EIPs
- **Security Tab**: AI-powered security findings
- **Cost Tab**: Cost analysis and optimization recommendations

## 🔒 Security Features

### AI-Powered Security Analysis
- **100+ Security Rules**: Automated detection of misconfigurations
- **Amazon Bedrock Integration**: Context-aware vulnerability analysis
- **Compliance Mapping**: CIS, PCI-DSS, HIPAA, GDPR, SOC2
- **Severity Scoring**: Critical, High, Medium, Low classifications

### Security Checks Include:
- IMDSv1 usage detection
- Public IP exposure
- Unencrypted storage (EBS, RDS, S3)
- Public database access
- Overly permissive security groups
- Missing MFA
- CloudTrail configuration
- Backup coverage gaps

## 💰 Cost Optimization

### Features:
- **Idle Resource Detection**: EC2 instances with low CPU/network usage
- **Right-Sizing Recommendations**: Instance type optimization
- **Storage Optimization**: GP2 to GP3 migration suggestions
- **Unused Resources**: Unattached EBS, unassociated EIPs
- **AI-Powered Analysis**: Bedrock-based cost optimization insights

## 🎯 Roadmap

### Planned Features (Real-Time Monitoring)
- [ ] Lambda-based 24/7 metric polling (every 5 minutes)
- [ ] SNS email alerting for threshold breaches
- [ ] DynamoDB alert history storage
- [ ] Real-time monitoring dashboard
- [ ] Alert resolution workflow
- [ ] Slack/Teams integration
- [ ] Mobile-responsive alerts view

## 📝 Project Structure

```
AWS_dashboard/
├── backend/
│   ├── app.py                      # Main Flask application
│   ├── ai_security_analyzer.py     # Bedrock security analysis
│   ├── cost_analyzer.py            # Cost analysis logic
│   ├── ai_cost_optimizer.py        # AI-powered cost optimization
│   ├── backup_coverage.py          # Backup coverage analyzer
│   ├── actual_billing_fetcher.py   # AWS Cost Explorer integration
│   └── requirements.txt            # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── AccountGroupManager.tsx
│   │   │   ├── ViewContent.tsx     # Main dashboard tabs
│   │   │   └── ...
│   │   ├── App.tsx
│   │   └── index.tsx
│   ├── package.json
│   └── tsconfig.json
├── .gitignore
└── README.md
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 👥 Authors

- **Your Name** - Initial work

## 🙏 Acknowledgments

- AWS SDK for Python (Boto3)
- Amazon Bedrock Nova Pro for AI analysis
- React and Material-UI communities

## 📞 Support

For issues and questions:
- Create an issue in the GitHub repository
- Contact: your-email@example.com

---

**Note**: This is a monitoring tool with ReadOnly access. It does not make any changes to customer AWS accounts.
