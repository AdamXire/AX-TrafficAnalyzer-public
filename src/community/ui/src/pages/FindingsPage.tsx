import { useEffect, useState } from 'react';
import { useAnalysisStore } from '../stores/analysisStore';
import { Card } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import type { Finding } from '../types/api';

const severityColors: Record<string, string> = {
  critical: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200',
  high: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200',
  low: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200',
  info: 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200',
};

export function FindingsPage() {
  const { findings, totalFindings, loading, fetchFindings } = useAnalysisStore();
  const [selectedSeverity, setSelectedSeverity] = useState<string>('');
  const [selectedCategory, setSelectedCategory] = useState<string>('');
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [page, setPage] = useState(0);
  const limit = 50;

  useEffect(() => {
    fetchFindings({
      severity: selectedSeverity || undefined,
      category: selectedCategory || undefined,
      limit,
      offset: page * limit,
    });
  }, [selectedSeverity, selectedCategory, page, fetchFindings]);

  const categories = Array.from(new Set(findings.map(f => f.category)));

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-bold">Security Findings</h1>
        <div className="text-sm text-gray-500">
          Total: {totalFindings} findings
        </div>
      </div>

      {/* Filters */}
      <Card className="p-4">
        <div className="flex gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium mb-2">Severity</label>
            <select
              value={selectedSeverity}
              onChange={(e) => {
                setSelectedSeverity(e.target.value);
                setPage(0);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md dark:bg-gray-700 dark:border-gray-600"
            >
              <option value="">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-sm font-medium mb-2">Category</label>
            <select
              value={selectedCategory}
              onChange={(e) => {
                setSelectedCategory(e.target.value);
                setPage(0);
              }}
              className="w-full px-3 py-2 border border-gray-300 rounded-md dark:bg-gray-700 dark:border-gray-600"
            >
              <option value="">All Categories</option>
              {categories.map((cat) => (
                <option key={cat} value={cat}>
                  {cat}
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Findings List */}
      <Card className="p-6">
        {loading ? (
          <div className="text-center py-8">Loading findings...</div>
        ) : findings.length === 0 ? (
          <div className="text-center py-8 text-gray-500">
            No findings found. Start capturing traffic to see analysis results.
          </div>
        ) : (
          <>
            <div className="space-y-4">
              {findings.map((finding) => (
                <div
                  key={finding.id}
                  className="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                  onClick={() => setSelectedFinding(finding)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-2">
                        <Badge className={severityColors[finding.severity]}>
                          {finding.severity.toUpperCase()}
                        </Badge>
                        <span className="text-sm text-gray-500">{finding.category}</span>
                        <span className="text-xs text-gray-400">
                          {new Date(finding.timestamp).toLocaleString()}
                        </span>
                      </div>
                      <h3 className="font-semibold text-lg mb-1">{finding.title}</h3>
                      <p className="text-sm text-gray-600 dark:text-gray-400">
                        {finding.description}
                      </p>
                      {finding.recommendation && (
                        <p className="text-sm text-blue-600 dark:text-blue-400 mt-2">
                          💡 {finding.recommendation}
                        </p>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Pagination */}
            <div className="mt-6 flex justify-between items-center">
              <button
                onClick={() => setPage(Math.max(0, page - 1))}
                disabled={page === 0}
                className="px-4 py-2 border rounded-md disabled:opacity-50"
              >
                Previous
              </button>
              <span className="text-sm text-gray-500">
                Page {page + 1} ({(page * limit) + 1}-{Math.min((page + 1) * limit, totalFindings)} of {totalFindings})
              </span>
              <button
                onClick={() => setPage(page + 1)}
                disabled={(page + 1) * limit >= totalFindings}
                className="px-4 py-2 border rounded-md disabled:opacity-50"
              >
                Next
              </button>
            </div>
          </>
        )}
      </Card>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          onClick={() => setSelectedFinding(null)}
        >
          <Card
            className="max-w-2xl w-full m-4 max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Badge className={severityColors[selectedFinding.severity]}>
                      {selectedFinding.severity.toUpperCase()}
                    </Badge>
                    <span className="text-sm text-gray-500">{selectedFinding.category}</span>
                  </div>
                  <h2 className="text-2xl font-bold">{selectedFinding.title}</h2>
                </div>
                <button
                  onClick={() => setSelectedFinding(null)}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>

              <div className="space-y-4">
                <div>
                  <h3 className="font-semibold mb-2">Description</h3>
                  <p className="text-gray-700 dark:text-gray-300">{selectedFinding.description}</p>
                </div>

                {selectedFinding.recommendation && (
                  <div>
                    <h3 className="font-semibold mb-2">Recommendation</h3>
                    <p className="text-blue-600 dark:text-blue-400">{selectedFinding.recommendation}</p>
                  </div>
                )}

                <div>
                  <h3 className="font-semibold mb-2">Details</h3>
                  <div className="text-sm space-y-1">
                    <div><strong>Finding ID:</strong> {selectedFinding.id}</div>
                    <div><strong>Session ID:</strong> {selectedFinding.session_id}</div>
                    {selectedFinding.flow_id && (
                      <div><strong>Flow ID:</strong> {selectedFinding.flow_id}</div>
                    )}
                    <div><strong>Timestamp:</strong> {new Date(selectedFinding.timestamp).toLocaleString()}</div>
                  </div>
                </div>

                {selectedFinding.metadata && Object.keys(selectedFinding.metadata).length > 0 && (
                  <div>
                    <h3 className="font-semibold mb-2">Metadata</h3>
                    <pre className="bg-gray-100 dark:bg-gray-800 p-3 rounded text-xs overflow-x-auto">
                      {JSON.stringify(selectedFinding.metadata, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

