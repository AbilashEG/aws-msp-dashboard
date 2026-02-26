# CloudWatch Metrics Integration - Complete Implementation Plan

## Overview
Implement CloudWatch metrics visualization with lazy loading approach.
Metrics are fetched ON-DEMAND when user clicks, not during initial scan.

---

## PHASE 1: BACKEND IMPLEMENTATION ✅ COMPLETED

### Step 1: CloudWatch Metrics Fetcher ✅
**File**: `cloudwatch_metrics_fetcher.py`
**Status**: Created

**Features**:
- EC2 metrics: CPU, Network, Disk, Status Checks
- RDS metrics: CPU, Connections, IOPS, Latency, Storage
- Lambda metrics: Invocations, Duration, Errors, Throttles
- ALB metrics: Requests, Response Time, Health Checks, HTTP codes
- NAT Gateway metrics: Bytes, Packets, Connections
- DynamoDB metrics: Read/Write capacity, Errors
- EBS metrics: Read/Write bytes/ops, Idle time
- CloudWatch Alarms for all resources
- 5-minute caching to avoid repeated API calls

---

### Step 2: API Endpoints in app.py
**Action**: Add these endpoints to Flask server in app.py

```python
# Add after existing Flask routes, before flask_app.run()

@flask_app.route('/metrics/ec2/<instance_id>', methods=['GET'])
def get_ec2_metrics(instance_id):
    """Get CloudWatch metrics for specific EC2 instance"""
    try:
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({'error': 'account_id required'}), 400
        
        # Assume role to get session
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        # Fetch metrics
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_ec2_metrics(instance_id, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch EC2 metrics: {e}")
        return jsonify({'error': str(e)}), 500


@flask_app.route('/metrics/rds/<db_instance_id>', methods=['GET'])
def get_rds_metrics(db_instance_id):
    """Get CloudWatch metrics for specific RDS instance"""
    try:
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({'error': 'account_id required'}), 400
        
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_rds_metrics(db_instance_id, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch RDS metrics: {e}")
        return jsonify({'error': str(e)}), 500


@flask_app.route('/metrics/lambda/<function_name>', methods=['GET'])
def get_lambda_metrics(function_name):
    """Get CloudWatch metrics for specific Lambda function"""
    try:
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({'error': 'account_id required'}), 400
        
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_lambda_metrics(function_name, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch Lambda metrics: {e}")
        return jsonify({'error': str(e)}), 500


@flask_app.route('/metrics/alb', methods=['GET'])
def get_alb_metrics():
    """Get CloudWatch metrics for specific ALB"""
    try:
        load_balancer_arn = request.args.get('arn')
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id or not load_balancer_arn:
            return jsonify({'error': 'account_id and arn required'}), 400
        
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_alb_metrics(load_balancer_arn, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch ALB metrics: {e}")
        return jsonify({'error': str(e)}), 500


@flask_app.route('/metrics/nat/<nat_gateway_id>', methods=['GET'])
def get_nat_metrics(nat_gateway_id):
    """Get CloudWatch metrics for specific NAT Gateway"""
    try:
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({'error': 'account_id required'}), 400
        
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_nat_gateway_metrics(nat_gateway_id, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch NAT Gateway metrics: {e}")
        return jsonify({'error': str(e)}), 500


@flask_app.route('/metrics/dynamodb/<table_name>', methods=['GET'])
def get_dynamodb_metrics(table_name):
    """Get CloudWatch metrics for specific DynamoDB table"""
    try:
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({'error': 'account_id required'}), 400
        
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_dynamodb_metrics(table_name, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch DynamoDB metrics: {e}")
        return jsonify({'error': str(e)}), 500


@flask_app.route('/metrics/ebs/<volume_id>', methods=['GET'])
def get_ebs_metrics(volume_id):
    """Get CloudWatch metrics for specific EBS volume"""
    try:
        region = request.args.get('region', 'us-east-1')
        hours = request.args.get('hours', 24, type=int)
        account_id = request.args.get('account_id')
        
        if not account_id:
            return jsonify({'error': 'account_id required'}), 400
        
        scanner = MSPMonitoringScanner()
        session = scanner.assume_role(account_id, CONFIG['DEFAULT_ROLE_NAME'])
        
        from cloudwatch_metrics_fetcher import CloudWatchMetricsFetcher
        fetcher = CloudWatchMetricsFetcher(session, region)
        metrics = fetcher.get_ebs_metrics(volume_id, hours)
        
        return jsonify({
            'status': 'success',
            'metrics': metrics,
            'fetchedAt': datetime.now(timezone.utc).isoformat()
        })
        
    except Exception as e:
        logger.error(f"Failed to fetch EBS metrics: {e}")
        return jsonify({'error': str(e)}), 500
```

---

## PHASE 2: FRONTEND IMPLEMENTATION

### Step 1: Install Recharts
```bash
cd frontend
npm install recharts
```

### Step 2: Create Metric Chart Components
**File**: `frontend/src/components/MetricChart.tsx`

```typescript
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

interface MetricChartProps {
  data: Array<{timestamp: string, value: number, unit: string}>;
  title: string;
  color: string;
  yAxisLabel?: string;
}

export function MetricChart({ data, title, color, yAxisLabel }: MetricChartProps) {
  if (!data || data.length === 0) {
    return (
      <div className="card p-8 text-center text-gray-400">
        <p>No data available for {title}</p>
      </div>
    );
  }

  const formattedData = data.map(d => ({
    time: new Date(d.timestamp).toLocaleString('en-US', { 
      month: 'short', 
      day: 'numeric', 
      hour: '2-digit' 
    }),
    value: d.value,
    unit: d.unit
  }));

  return (
    <div className="card">
      <h3 className="text-lg font-bold text-gray-300 mb-4">{title}</h3>
      <ResponsiveContainer width="100%" height={300}>
        <LineChart data={formattedData}>
          <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
          <XAxis 
            dataKey="time" 
            stroke="#9ca3af" 
            style={{ fontSize: '12px' }}
          />
          <YAxis 
            stroke="#9ca3af" 
            label={{ value: yAxisLabel, angle: -90, position: 'insideLeft', style: { fill: '#9ca3af' } }}
          />
          <Tooltip 
            contentStyle={{ 
              backgroundColor: '#1f2937', 
              border: '1px solid #374151',
              borderRadius: '8px'
            }}
            labelStyle={{ color: '#9ca3af' }}
            formatter={(value: any, name: any, props: any) => [
              `${value.toFixed(2)} ${props.payload.unit}`,
              title
            ]}
          />
          <Legend />
          <Line 
            type="monotone" 
            dataKey="value" 
            stroke={color} 
            strokeWidth={2}
            dot={false}
            name={title}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
```

### Step 3: Create CloudWatch Metrics View
**File**: `frontend/src/components/CloudWatchMetrics.tsx`

```typescript
import { useState } from 'react';
import { MetricChart } from './MetricChart';

interface CloudWatchMetricsProps {
  scanData: any;
  accountId: string;
}

export function CloudWatchMetrics({ scanData, accountId }: CloudWatchMetricsProps) {
  const [selectedService, setSelectedService] = useState<string | null>(null);
  const [selectedResource, setSelectedResource] = useState<any>(null);
  const [metrics, setMetrics] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const fetchMetrics = async (service: string, resourceId: string, region: string, additionalParams?: any) => {
    setLoading(true);
    try {
      let url = '';
      const params = new URLSearchParams({
        account_id: accountId,
        region: region,
        hours: '24'
      });

      switch (service) {
        case 'ec2':
          url = `/metrics/ec2/${resourceId}?${params}`;
          break;
        case 'rds':
          url = `/metrics/rds/${resourceId}?${params}`;
          break;
        case 'lambda':
          url = `/metrics/lambda/${resourceId}?${params}`;
          break;
        case 'alb':
          params.append('arn', additionalParams.arn);
          url = `/metrics/alb?${params}`;
          break;
        case 'nat':
          url = `/metrics/nat/${resourceId}?${params}`;
          break;
        case 'dynamodb':
          url = `/metrics/dynamodb/${resourceId}?${params}`;
          break;
        case 'ebs':
          url = `/metrics/ebs/${resourceId}?${params}`;
          break;
      }

      const response = await fetch(`http://localhost:5000${url}`);
      const data = await response.json();
      
      if (data.status === 'success') {
        setMetrics(data.metrics);
      } else {
        console.error('Failed to fetch metrics:', data.error);
      }
    } catch (error) {
      console.error('Error fetching metrics:', error);
    } finally {
      setLoading(false);
    }
  };

  const renderServiceList = () => {
    const details = scanData?.inventoryDetails;
    if (!details) return null;

    const services = [
      { key: 'ec2', name: 'EC2 Instances', count: details.ec2?.total || 0 },
      { key: 'rds', name: 'RDS Databases', count: details.rds?.total || 0 },
      { key: 'lambda', name: 'Lambda Functions', count: details.lambda?.total || 0 },
      { key: 'alb', name: 'Load Balancers', count: details.alb?.total || 0 },
      { key: 'nat_gateway', name: 'NAT Gateways', count: details.nat_gateway?.total || 0 },
      { key: 'dynamodb', name: 'DynamoDB Tables', count: details.dynamodb?.total || 0 },
      { key: 'ebs', name: 'EBS Volumes', count: details.ebs?.total || 0 },
    ];

    return (
      <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">
        {services.map(service => (
          <div
            key={service.key}
            onClick={() => setSelectedService(service.key)}
            className={`card cursor-pointer hover:border-orange-500 transition-all ${
              selectedService === service.key ? 'border-orange-500 bg-gray-800' : ''
            }`}
          >
            <h3 className="text-lg font-medium text-gray-300">{service.name}</h3>
            <p className="text-4xl font-bold text-orange-500 mt-2">{service.count}</p>
            <p className="text-sm text-gray-400 mt-2">Click to view metrics</p>
          </div>
        ))}
      </div>
    );
  };

  const renderResourceList = () => {
    if (!selectedService) return null;

    const details = scanData?.inventoryDetails;
    let resources = [];
    let serviceKey = selectedService;

    // Map service keys to inventory keys
    if (selectedService === 'nat_gateway') serviceKey = 'nat_gateway';
    
    resources = details[serviceKey]?.details || [];

    if (resources.length === 0) {
      return (
        <div className="card text-center py-12">
          <p className="text-gray-400">No resources found for this service</p>
        </div>
      );
    }

    return (
      <div className="space-y-4">
        <h3 className="text-2xl font-bold text-orange-500">
          Select a resource to view metrics
        </h3>
        <div className="grid grid-cols-1 gap-4">
          {resources.map((resource: any, idx: number) => {
            const resourceId = resource.instanceId || resource.dbInstanceIdentifier || 
                             resource.functionName || resource.loadBalancerName ||
                             resource.natGatewayId || resource.tableName || resource.volumeId;
            const region = resource.region || 'us-east-1';

            return (
              <div
                key={idx}
                onClick={() => {
                  setSelectedResource(resource);
                  fetchMetrics(selectedService, resourceId, region, { arn: resource.arn });
                }}
                className="card cursor-pointer hover:border-green-500 transition-all"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <p className="font-mono text-orange-400 font-bold">{resourceId}</p>
                    <p className="text-sm text-gray-400 mt-1">Region: {region}</p>
                    {resource.state && (
                      <span className={`inline-block px-3 py-1 rounded-full text-xs mt-2 ${
                        resource.state === 'running' || resource.state === 'available' 
                          ? 'bg-green-900/40 text-green-300' 
                          : 'bg-gray-700 text-gray-300'
                      }`}>
                        {resource.state}
                      </span>
                    )}
                  </div>
                  <button className="px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg transition-colors">
                    View Metrics →
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  const renderMetrics = () => {
    if (!metrics || loading) {
      return (
        <div className="card text-center py-12">
          <p className="text-gray-400">{loading ? 'Loading metrics...' : 'Select a resource to view metrics'}</p>
        </div>
      );
    }

    // Render different metrics based on service type
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h3 className="text-2xl font-bold text-orange-500">
            Metrics for {selectedResource?.instanceId || selectedResource?.dbInstanceIdentifier || 
                        selectedResource?.functionName || selectedResource?.loadBalancerName ||
                        selectedResource?.natGatewayId || selectedResource?.tableName || 
                        selectedResource?.volumeId}
          </h3>
          <button
            onClick={() => {
              setSelectedResource(null);
              setMetrics(null);
            }}
            className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded-lg"
          >
            ← Back
          </button>
        </div>

        {/* EC2 Metrics */}
        {selectedService === 'ec2' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <MetricChart data={metrics.cpuUtilization} title="CPU Utilization" color="#f97316" yAxisLabel="Percent (%)" />
            <MetricChart data={metrics.networkIn} title="Network In" color="#3b82f6" yAxisLabel="Bytes" />
            <MetricChart data={metrics.networkOut} title="Network Out" color="#8b5cf6" yAxisLabel="Bytes" />
            <MetricChart data={metrics.diskReadOps} title="Disk Read Ops" color="#10b981" yAxisLabel="Count" />
          </div>
        )}

        {/* RDS Metrics */}
        {selectedService === 'rds' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <MetricChart data={metrics.cpuUtilization} title="CPU Utilization" color="#f97316" yAxisLabel="Percent (%)" />
            <MetricChart data={metrics.databaseConnections} title="Database Connections" color="#3b82f6" yAxisLabel="Count" />
            <MetricChart data={metrics.readIOPS} title="Read IOPS" color="#10b981" yAxisLabel="Count/Second" />
            <MetricChart data={metrics.writeIOPS} title="Write IOPS" color="#8b5cf6" yAxisLabel="Count/Second" />
          </div>
        )}

        {/* Lambda Metrics */}
        {selectedService === 'lambda' && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <MetricChart data={metrics.invocations} title="Invocations" color="#f97316" yAxisLabel="Count" />
            <MetricChart data={metrics.duration} title="Duration" color="#3b82f6" yAxisLabel="Milliseconds" />
            <MetricChart data={metrics.errors} title="Errors" color="#ef4444" yAxisLabel="Count" />
            <MetricChart data={metrics.throttles} title="Throttles" color="#f59e0b" yAxisLabel="Count" />
          </div>
        )}

        {/* CloudWatch Alarms */}
        {metrics.alarms && metrics.alarms.length > 0 && (
          <div className="card">
            <h4 className="text-lg font-bold text-gray-300 mb-4">CloudWatch Alarms</h4>
            <div className="space-y-2">
              {metrics.alarms.map((alarm: any, idx: number) => (
                <div key={idx} className="flex items-center justify-between p-3 bg-gray-800 rounded">
                  <div>
                    <p className="font-medium text-gray-200">{alarm.alarmName}</p>
                    <p className="text-sm text-gray-400">{alarm.metricName} {alarm.comparisonOperator} {alarm.threshold}</p>
                  </div>
                  <span className={`px-3 py-1 rounded ${
                    alarm.state === 'OK' ? 'bg-green-900/40 text-green-300' :
                    alarm.state === 'ALARM' ? 'bg-red-900/40 text-red-300' :
                    'bg-gray-700 text-gray-300'
                  }`}>
                    {alarm.state}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-8">
      <h2 className="text-3xl font-bold text-orange-500">CloudWatch Metrics</h2>
      
      {!selectedService && renderServiceList()}
      {selectedService && !selectedResource && renderResourceList()}
      {selectedResource && renderMetrics()}
    </div>
  );
}
```

### Step 4: Add CloudWatch Tab to ViewContent.tsx

```typescript
// In ViewContent.tsx, add new case:

case 'cloudwatch':
  return <CloudWatchMetrics scanData={scanData} accountId={scanData?.accountId || '091605603734'} />;
```

### Step 5: Add CloudWatch to Sidebar Navigation

```typescript
// In Sidebar.tsx or navigation component, add:
{
  id: 'cloudwatch',
  name: 'CloudWatch Metrics',
  icon: '📊'
}
```

---

## TESTING CHECKLIST

### Backend Testing
- [ ] Start backend: `python app.py`
- [ ] Test EC2 metrics endpoint: `GET /metrics/ec2/i-xxxxx?account_id=xxx&region=ap-south-1`
- [ ] Test RDS metrics endpoint: `GET /metrics/rds/db-xxxxx?account_id=xxx&region=ap-south-1`
- [ ] Verify 5-minute caching works
- [ ] Check logs for API call counts

### Frontend Testing
- [ ] Install recharts: `npm install recharts`
- [ ] Start frontend: `npm run dev`
- [ ] Click "CloudWatch" tab
- [ ] Select service (EC2)
- [ ] Click resource
- [ ] Verify graphs load
- [ ] Check alarm display
- [ ] Test back navigation

---

## PERFORMANCE NOTES

- **Caching**: 5-minute TTL on metrics prevents repeated API calls
- **Lazy Loading**: Metrics only fetched when user clicks "View Metrics"
- **API Limits**: CloudWatch GetMetricStatistics = 400 TPS (very high)
- **Cost**: CloudWatch API calls are FREE (included in AWS pricing)

---

## NEXT STEPS

1. Add API endpoints to app.py (copy from Step 2 above)
2. Install recharts in frontend
3. Create MetricChart.tsx component
4. Create CloudWatchMetrics.tsx component
5. Add 'cloudwatch' case to ViewContent.tsx
6. Add CloudWatch to sidebar navigation
7. Test with real account data

---

## FUTURE ENHANCEMENTS

- Add time range selector (1h, 6h, 24h, 7d, 30d)
- Add metric comparison (compare multiple resources)
- Add custom metric queries
- Export metrics to CSV
- Set up CloudWatch alarms from UI
- Add anomaly detection visualization
