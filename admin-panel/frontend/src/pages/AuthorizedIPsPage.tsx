import React, { useEffect, useState } from 'react';
import { Plus, Trash2, AlertTriangle, CheckCircle, Lock } from 'lucide-react';
import apiClient from '../api/client';

export const AuthorizedIPsPage = () => {
  const [ips, setIps] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [newIp, setNewIp] = useState('');
  const [duration, setDuration] = useState(5000);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    loadIps();
    const interval = setInterval(loadIps, 3000);
    return () => clearInterval(interval);
  }, []);

  const loadIps = async () => {
    try {
      const data = await apiClient.getAuthorizedIps();
      setIps(data.authorized_ips || []);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to load IPs');
    } finally {
      setLoading(false);
    }
  };

  const handleAddIp = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newIp.trim()) return;

    setSubmitting(true);
    try {
      await apiClient.authorizeIp(newIp, duration);
      setNewIp('');
      await loadIps();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to authorize IP');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRevokeIp = async (ip: string) => {
    try {
      await apiClient.revokeIp(ip);
      await loadIps();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to revoke IP');
    }
  };

  const handleRevokeAll = async () => {
    if (!window.confirm('Revoke all authorized IPs? This cannot be undone.')) return;

    try {
      await apiClient.revokeAllIps();
      await loadIps();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to revoke all IPs');
    }
  };

  if (loading) {
    return <div className="text-center text-slate-400 py-8">Loading...</div>;
  }

  const activeIps = ips.filter(ip => ip.authorized);
  const expiredIps = ips.filter(ip => !ip.authorized);

  return (
    <div className="space-y-6">
      {/* Error Message */}
      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 flex gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400 text-sm">{error}</p>
        </div>
      )}

      {/* Add IP Form */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-bold text-white mb-4">Authorize New IP</h3>
        <form onSubmit={handleAddIp} className="flex gap-4 flex-wrap">
          <input
            type="text"
            value={newIp}
            onChange={(e) => setNewIp(e.target.value)}
            placeholder="Enter IP address (e.g., 192.168.1.100)"
            className="flex-1 min-w-[200px] px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-400 focus:outline-none focus:border-blue-500"
            disabled={submitting}
          />
          <select
            value={duration}
            onChange={(e) => setDuration(Number(e.target.value))}
            className="px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:border-blue-500"
            disabled={submitting}
          >
            <option value={5000}>5 seconds</option>
            <option value={30000}>30 seconds</option>
            <option value={60000}>1 minute</option>
            <option value={300000}>5 minutes</option>
            <option value={3600000}>1 hour</option>
          </select>
          <button
            type="submit"
            disabled={submitting}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors disabled:bg-slate-600 flex items-center gap-2"
          >
            <Plus className="w-5 h-5" />
            Authorize
          </button>
        </form>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <p className="text-slate-400 text-sm mb-1">Active Authorizations</p>
          <p className="text-3xl font-bold text-green-400">{activeIps.length}</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <p className="text-slate-400 text-sm mb-1">Expired Entries</p>
          <p className="text-3xl font-bold text-slate-300">{expiredIps.length}</p>
        </div>
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <p className="text-slate-400 text-sm mb-1">Total Entries</p>
          <p className="text-3xl font-bold text-blue-400">{ips.length}</p>
        </div>
      </div>

      {/* Active IPs Table */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
        <div className="bg-slate-900 px-6 py-4 border-b border-slate-700">
          <div className="flex justify-between items-center">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <CheckCircle className="w-5 h-5 text-green-500" />
              Active Authorizations ({activeIps.length})
            </h3>
            {activeIps.length > 0 && (
              <button
                onClick={handleRevokeAll}
                className="text-red-400 hover:text-red-300 text-sm font-semibold flex items-center gap-1"
              >
                <Trash2 className="w-4 h-4" />
                Revoke All
              </button>
            )}
          </div>
        </div>

        {activeIps.length === 0 ? (
          <div className="px-6 py-8 text-center text-slate-400">
            <Lock className="w-12 h-12 mx-auto mb-2 opacity-50" />
            <p>No active authorizations</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-900/50">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">TTL (seconds)</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">Expires At (ns)</th>
                  <th className="px-6 py-3 text-right text-xs font-semibold text-slate-400">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {activeIps.map((ip, idx) => (
                  <tr key={idx} className="hover:bg-slate-700/50 transition-colors">
                    <td className="px-6 py-3 font-mono text-white">{ip.ip}</td>
                    <td className="px-6 py-3">
                      <span className="text-green-400 font-semibold">{ip.ttl_seconds}s</span>
                    </td>
                    <td className="px-6 py-3 text-slate-400 text-sm">{ip.expires_ns}</td>
                    <td className="px-6 py-3 text-right">
                      <button
                        onClick={() => handleRevokeIp(ip.ip)}
                        className="text-red-400 hover:text-red-300 font-semibold text-sm"
                      >
                        Revoke
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Expired IPs Table */}
      {expiredIps.length > 0 && (
        <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
          <div className="bg-slate-900 px-6 py-4 border-b border-slate-700">
            <h3 className="text-lg font-bold text-white flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-yellow-500" />
              Expired Entries ({expiredIps.length})
            </h3>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-900/50">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">Expired</th>
                  <th className="px-6 py-3 text-right text-xs font-semibold text-slate-400">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {expiredIps.map((ip, idx) => (
                  <tr key={idx} className="hover:bg-slate-700/50 transition-colors opacity-60">
                    <td className="px-6 py-3 font-mono text-slate-300">{ip.ip}</td>
                    <td className="px-6 py-3 text-yellow-400 text-sm">✓ Expired</td>
                    <td className="px-6 py-3 text-right">
                      <button
                        onClick={() => handleRevokeIp(ip.ip)}
                        className="text-red-400 hover:text-red-300 font-semibold text-sm"
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
