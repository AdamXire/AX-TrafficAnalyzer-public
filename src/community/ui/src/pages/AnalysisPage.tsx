import { useEffect, useState } from 'react';
import { useAnalysisStore } from '../stores/analysisStore';
import { Card } from '../components/ui/card';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, PieChart, Pie, Cell, ResponsiveContainer } from 'recharts';

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
};

export function AnalysisPage() {
  const { stats, fetchStats, fetchFindings } = useAnalysisStore();
  const [timeRange, setTimeRange] = useState<'all' | 'today' | 'week'>('all');

  useEffect(() => {
    fetchStats();
    fetchFindings({ limit: 1000 }); // Get all for charts
  }, [fetchStats, fetchFindings]);

  // Prepare chart data
  const severityData = stats?.by_severity
    ? Object.entries(stats.by_severity).map(([severity, count]) => ({
        severity: severity.toUpperCase(),
        count,
      }))
    : [];

  const categoryData = stats?.top_categories
    ? Object.entries(stats.top_categories)
        .slice(0, 10)
        .map(([category, count]) => ({
          category: category.length > 20 ? category.substring(0, 20) + '...' : category,
          count,
        }))
    : [];

  const pieData = severityData.map((item) => ({
    name: item.severity,
    value: item.count,
  }));

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Analysis Dashboard</h1>
        <select
          value={timeRange}
          onChange={(e) => setTimeRange(e.target.value as any)}
          className="px-3 py-2 border border-gray-300 rounded-md dark:bg-gray-700 dark:border-gray-600"
        >
          <option value="all">All Time</option>
          <option value="week">Last 7 Days</option>
          <option value="today">Today</option>
        </select>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-6">
        <Card className="p-6">
          <h3 className="text-sm text-gray-500 mb-2">Total Findings</h3>
          <p className="text-3xl font-bold">{stats?.total_findings || 0}</p>
        </Card>
        <Card className="p-6">
          <h3 className="text-sm text-gray-500 mb-2">Critical</h3>
          <p className="text-3xl font-bold text-red-600">
            {stats?.by_severity?.critical || 0}
          </p>
        </Card>
        <Card className="p-6">
          <h3 className="text-sm text-gray-500 mb-2">High</h3>
          <p className="text-3xl font-bold text-orange-600">
            {stats?.by_severity?.high || 0}
          </p>
        </Card>
        <Card className="p-6">
          <h3 className="text-sm text-gray-500 mb-2">Medium</h3>
          <p className="text-3xl font-bold text-yellow-600">
            {stats?.by_severity?.medium || 0}
          </p>
        </Card>
      </div>

      {/* Charts */}
      <div className="grid grid-cols-2 gap-6">
        {/* Severity Distribution (Pie) */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Findings by Severity</h3>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={pieData}
                  cx="50%"
                  cy="50%"
                  labelLine={false}
                  label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
                  outerRadius={80}
                  fill="#8884d8"
                  dataKey="value"
                >
                  {pieData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={severityColors[entry.name.toLowerCase()] || '#8884d8'} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-center py-12 text-gray-500">No data available</div>
          )}
        </Card>

        {/* Severity Bar Chart */}
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={300}>
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="severity" />
                <YAxis />
                <Tooltip />
                <Legend />
                <Bar dataKey="count" fill="#3b82f6">
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={severityColors[entry.severity.toLowerCase()] || '#3b82f6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="text-center py-12 text-gray-500">No data available</div>
          )}
        </Card>
      </div>

      {/* Top Categories */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Top Categories</h3>
        {categoryData.length > 0 ? (
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={categoryData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis type="number" />
              <YAxis dataKey="category" type="category" width={150} />
              <Tooltip />
              <Legend />
              <Bar dataKey="count" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        ) : (
          <div className="text-center py-12 text-gray-500">No data available</div>
        )}
      </Card>

      {/* Orchestrator Metrics */}
      {stats?.orchestrator_metrics && Object.keys(stats.orchestrator_metrics).length > 0 && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4">Analysis Performance</h3>
          <div className="grid grid-cols-3 gap-4">
            <div>
              <div className="text-sm text-gray-500">Total Flows Analyzed</div>
              <div className="text-2xl font-bold">
                {stats.orchestrator_metrics.total_flows || 0}
              </div>
            </div>
            <div>
              <div className="text-sm text-gray-500">Throughput (flows/sec)</div>
              <div className="text-2xl font-bold">
                {stats.orchestrator_metrics.throughput?.toFixed(2) || '0.00'}
              </div>
            </div>
            <div>
              <div className="text-sm text-gray-500">Avg Analysis Time (ms)</div>
              <div className="text-2xl font-bold">
                {stats.orchestrator_metrics.avg_analysis_time_ms?.toFixed(0) || '0'}
              </div>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}

