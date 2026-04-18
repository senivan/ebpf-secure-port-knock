import React, { useEffect, useState } from 'react';
import { Play, AlertTriangle, CheckCircle } from 'lucide-react';
import apiClient from '../api/client';

export const TestingPage = () => {
  const [activeTab, setActiveTab] = useState<'knock' | 'connectivity' | 'health'>('knock');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [results, setResults] = useState<any>(null);

  // Knock packet test form
  const [knockForm, setKnockForm] = useState({
    src_ip: '192.168.1.100',
    dst_ip: '192.168.1.1',
    hmac_key: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff',
    dst_port: '40000',
    ifname: 'eth0'
  });

  // Connectivity test form
  const [connectForm, setConnectForm] = useState({
    target: '192.168.1.1',
    port: '22'
  });

  const handleKnockChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setKnockForm(prev => ({ ...prev, [name]: value }));
  };

  const handleConnectChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setConnectForm(prev => ({ ...prev, [name]: value }));
  };

  const testKnockPacket = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const result = await apiClient.sendKnockPacket(
        knockForm.src_ip,
        knockForm.dst_ip,
        knockForm.hmac_key,
        parseInt(knockForm.dst_port),
        knockForm.ifname
      );

      setResults(result);
      if (result.success) {
        setSuccess('Knock packet sent successfully');
      } else {
        setError(result.error || 'Failed to send knock packet');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Test failed');
    } finally {
      setLoading(false);
    }
  };

  const testConnectivity = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const result = await apiClient.testConnectivity(
        connectForm.target,
        parseInt(connectForm.port)
      );

      setResults(result);
      if (result.ping.success || result.port_open) {
        setSuccess('Connectivity test completed');
      }
    } catch (err: any) {
      setError(err.response?.data?.error || 'Test failed');
    } finally {
      setLoading(false);
    }
  };

  const testSystemHealth = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const result = await apiClient.testSystemHealth();
      setResults(result);
      setSuccess('System health check completed');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Test failed');
    } finally {
      setLoading(false);
    }
  };

  const testMapsIntegrity = async () => {
    setLoading(true);
    setError('');
    setSuccess('');

    try {
      const result = await apiClient.testMapsIntegrity();
      setResults(result);
      setSuccess('Maps integrity check completed');
    } catch (err: any) {
      setError(err.response?.data?.error || 'Test failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Error/Success Messages */}
      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 flex gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400">{error}</p>
        </div>
      )}

      {success && (
        <div className="bg-green-900/20 border border-green-700 rounded-lg p-4 flex gap-3">
          <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
          <p className="text-green-400">{success}</p>
        </div>
      )}

      {/* Tabs */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
        <div className="flex border-b border-slate-700">
          {['knock', 'connectivity', 'health'].map(tab => (
            <button
              key={tab}
              onClick={() => { setActiveTab(tab as any); setResults(null); }}
              className={`flex-1 px-4 py-3 font-semibold transition-colors ${
                activeTab === tab
                  ? 'bg-blue-600 text-white'
                  : 'text-slate-400 hover:text-white'
              }`}
            >
              {tab.charAt(0).toUpperCase() + tab.slice(1)}
            </button>
          ))}
        </div>

        <div className="p-6">
          {/* Knock Packet Test */}
          {activeTab === 'knock' && (
            <div className="space-y-4">
              <h3 className="text-lg font-bold text-white mb-4">Test Knock Packet</h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 text-sm font-semibold mb-2">Source IP</label>
                  <input
                    type="text"
                    name="src_ip"
                    value={knockForm.src_ip}
                    onChange={handleKnockChange}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-semibold mb-2">Destination IP</label>
                  <input
                    type="text"
                    name="dst_ip"
                    value={knockForm.dst_ip}
                    onChange={handleKnockChange}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-semibold mb-2">Knock Port</label>
                  <input
                    type="text"
                    name="dst_port"
                    value={knockForm.dst_port}
                    onChange={handleKnockChange}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-semibold mb-2">Interface</label>
                  <input
                    type="text"
                    name="ifname"
                    value={knockForm.ifname}
                    onChange={handleKnockChange}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 text-sm font-semibold mb-2">HMAC Key (Hex)</label>
                <textarea
                  name="hmac_key"
                  value={knockForm.hmac_key}
                  onChange={handleKnockChange as any}
                  className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white font-mono text-xs focus:outline-none focus:border-blue-500"
                  rows={2}
                />
              </div>

              <button
                onClick={testKnockPacket}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors disabled:bg-slate-600 flex items-center gap-2"
              >
                <Play className="w-5 h-5" />
                {loading ? 'Sending...' : 'Send Knock Packet'}
              </button>
            </div>
          )}

          {/* Connectivity Test */}
          {activeTab === 'connectivity' && (
            <div className="space-y-4">
              <h3 className="text-lg font-bold text-white mb-4">Test Connectivity</h3>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-slate-300 text-sm font-semibold mb-2">Target IP</label>
                  <input
                    type="text"
                    name="target"
                    value={connectForm.target}
                    onChange={handleConnectChange}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div>
                  <label className="block text-slate-300 text-sm font-semibold mb-2">Target Port</label>
                  <input
                    type="text"
                    name="port"
                    value={connectForm.port}
                    onChange={handleConnectChange}
                    className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
                  />
                </div>
              </div>

              <button
                onClick={testConnectivity}
                disabled={loading}
                className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors disabled:bg-slate-600 flex items-center gap-2"
              >
                <Play className="w-5 h-5" />
                {loading ? 'Testing...' : 'Test Connectivity'}
              </button>
            </div>
          )}

          {/* Health Checks */}
          {activeTab === 'health' && (
            <div className="space-y-4">
              <h3 className="text-lg font-bold text-white mb-4">System Health & Diagnostics</h3>

              <div className="space-y-2">
                <button
                  onClick={testSystemHealth}
                  disabled={loading}
                  className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors disabled:bg-slate-600 flex items-center gap-2"
                >
                  <Play className="w-5 h-5" />
                  {loading && activeTab === 'health' ? 'Running...' : 'Run System Health Check'}
                </button>

                <button
                  onClick={testMapsIntegrity}
                  disabled={loading}
                  className="w-full bg-purple-600 hover:bg-purple-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors disabled:bg-slate-600 flex items-center gap-2"
                >
                  <Play className="w-5 h-5" />
                  {loading && activeTab === 'health' ? 'Checking...' : 'Check Maps Integrity'}
                </button>
              </div>
            </div>
          )}

          {/* Results */}
          {results && (
            <div className="mt-6 p-4 bg-slate-700 rounded-lg border border-slate-600">
              <h4 className="text-white font-semibold mb-2">Results:</h4>
              <pre className="text-slate-300 text-xs overflow-x-auto">
                {JSON.stringify(results, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
