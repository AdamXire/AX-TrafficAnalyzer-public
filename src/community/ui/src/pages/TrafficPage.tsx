import { useEffect, useState } from 'react';
import { useTrafficStore } from '../stores/trafficStore';
import { useAnalysisStore } from '../stores/analysisStore';
import { Card } from '../components/ui/card';
import { Badge } from '../components/ui/badge';
import { wsClient } from '../lib/websocket';
import type { Flow, ProtocolAnalysis, ThreatIntel } from '../types/api';

export function TrafficPage() {
  const { flows, fetchFlows, addFlow } = useTrafficStore();
  const { getProtocolAnalysis, getThreatIntel } = useAnalysisStore();
  const [selectedFlow, setSelectedFlow] = useState<Flow | null>(null);
  const [protocolAnalysis, setProtocolAnalysis] = useState<ProtocolAnalysis | null>(null);
  const [threatIntel, setThreatIntel] = useState<Record<string, ThreatIntel>>({});
  const [loadingAnalysis, setLoadingAnalysis] = useState(false);
  
  useEffect(() => {
    fetchFlows({ limit: 100 });
    wsClient.on('http_flow', addFlow);
    
    return () => {
      wsClient.off('http_flow', addFlow);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  
  const handleFlowClick = async (flow: Flow) => {
    setSelectedFlow(flow);
    setLoadingAnalysis(true);
    
    // Fetch protocol analysis
    const analysis = await getProtocolAnalysis(flow.flow_id);
    setProtocolAnalysis(analysis);
    
    // Fetch threat intel for host
    if (flow.host && !threatIntel[flow.host]) {
      const intel = await getThreatIntel(flow.host);
      if (intel) {
        setThreatIntel(prev => ({ ...prev, [flow.host]: intel }));
      }
    }
    
    setLoadingAnalysis(false);
  };
  
  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'bg-green-100 text-green-800';
    if (status >= 300 && status < 400) return 'bg-blue-100 text-blue-800';
    if (status >= 400 && status < 500) return 'bg-yellow-100 text-yellow-800';
    if (status >= 500) return 'bg-red-100 text-red-800';
    return 'bg-gray-100 text-gray-800';
  };
  
  return (
    <div className="space-y-6">
      <h1 className="text-3xl font-bold">Traffic Viewer</h1>
      
      <Card className="p-6">
        <table className="w-full">
          <thead>
            <tr className="border-b">
              <th className="text-left p-2">Method</th>
              <th className="text-left p-2">URL</th>
              <th className="text-left p-2">Status</th>
              <th className="text-left p-2">Size</th>
              <th className="text-left p-2">Time</th>
              <th className="text-left p-2">Analysis</th>
            </tr>
          </thead>
          <tbody>
            {flows.length === 0 ? (
              <tr>
                <td colSpan={6} className="p-4 text-center text-gray-500">
                  No traffic data available
                </td>
              </tr>
            ) : (
              flows.map((flow) => {
                const intel = threatIntel[flow.host];
                return (
                  <tr
                    key={flow.flow_id}
                    className="border-b hover:bg-gray-50 dark:hover:bg-gray-800 cursor-pointer"
                    onClick={() => handleFlowClick(flow)}
                  >
                    <td className="p-2">
                      <Badge>{flow.method}</Badge>
                    </td>
                    <td className="p-2 truncate max-w-md" title={flow.url}>
                      {flow.url}
                    </td>
                    <td className="p-2">
                      <Badge className={getStatusColor(flow.status_code)}>
                        {flow.status_code}
                      </Badge>
                    </td>
                    <td className="p-2">{flow.response_size} bytes</td>
                    <td className="p-2">{new Date(flow.timestamp).toLocaleTimeString()}</td>
                    <td className="p-2">
                      {intel && (
                        <Badge
                          className={
                            intel.reputation === 'malicious'
                              ? 'bg-red-100 text-red-800'
                              : intel.reputation === 'suspicious'
                              ? 'bg-yellow-100 text-yellow-800'
                              : 'bg-green-100 text-green-800'
                          }
                        >
                          {intel.reputation}
                        </Badge>
                      )}
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </Card>

      {/* Flow Analysis Modal */}
      {selectedFlow && (
        <div
          className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50"
          onClick={() => {
            setSelectedFlow(null);
            setProtocolAnalysis(null);
          }}
        >
          <Card
            className="max-w-4xl w-full m-4 max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="p-6">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h2 className="text-2xl font-bold mb-2">Flow Analysis</h2>
                  <div className="text-sm text-gray-500 space-y-1">
                    <div><strong>Flow ID:</strong> {selectedFlow.flow_id}</div>
                    <div><strong>URL:</strong> {selectedFlow.url}</div>
                    <div><strong>Method:</strong> {selectedFlow.method}</div>
                    <div><strong>Status:</strong> {selectedFlow.status_code}</div>
                    <div><strong>Host:</strong> {selectedFlow.host}</div>
                  </div>
                </div>
                <button
                  onClick={() => {
                    setSelectedFlow(null);
                    setProtocolAnalysis(null);
                  }}
                  className="text-gray-500 hover:text-gray-700"
                >
                  ✕
                </button>
              </div>

              {/* Threat Intelligence */}
              {threatIntel[selectedFlow.host] && (
                <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <h3 className="font-semibold mb-2">Threat Intelligence</h3>
                  <div className="text-sm">
                    <div><strong>Domain:</strong> {threatIntel[selectedFlow.host].domain}</div>
                    <div><strong>Reputation:</strong> {threatIntel[selectedFlow.host].reputation}</div>
                    {threatIntel[selectedFlow.host].sources.length > 0 && (
                      <div><strong>Sources:</strong> {threatIntel[selectedFlow.host].sources.join(', ')}</div>
                    )}
                  </div>
                </div>
              )}

              {/* Protocol Analysis */}
              {loadingAnalysis ? (
                <div className="text-center py-8">Loading analysis...</div>
              ) : protocolAnalysis ? (
                <div>
                  <h3 className="font-semibold mb-4">Protocol Analysis</h3>
                  {Object.keys(protocolAnalysis.analyzers).length > 0 ? (
                    <div className="space-y-4">
                      {Object.entries(protocolAnalysis.analyzers).map(([analyzerName, result]) => (
                        <div key={analyzerName} className="border rounded-lg p-4">
                          <h4 className="font-semibold mb-2">{analyzerName}</h4>
                          {result.findings && result.findings.length > 0 ? (
                            <div className="space-y-2">
                              <div className="text-sm text-gray-600">
                                Found {result.findings.length} issue(s)
                              </div>
                              {result.findings.slice(0, 5).map((finding) => (
                                <div key={finding.id} className="text-sm p-2 bg-yellow-50 dark:bg-yellow-900 rounded">
                                  <Badge className="mr-2">{finding.severity}</Badge>
                                  {finding.title}
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-sm text-gray-500">No issues detected</div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-gray-500">No analysis results available</div>
                  )}
                </div>
              ) : (
                <div className="text-sm text-gray-500">Click on a flow to view analysis details</div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  );
}

