import React, { useEffect, useState } from 'react';
import { Activity, Shield, AlertTriangle, CheckCircle } from 'lucide-react';
import apiClient from '../api/client';

export const Dashboard = () => {
  const [status, setStatus] = useState<any>(null);
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000); // Refresh every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadData = async () => {
    try {
      const [statusData, statsData] = await Promise.all([
        apiClient.getSystemStatus(),
        apiClient.getStats()
      ]);
      setStatus(statusData);
      setStats(statsData);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to load data');
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return <div className="text-center text-slate-400 py-8">Loading...</div>;
  }

  if (error) {
    return <div className="text-center text-red-400 py-8">{error}</div>;
  }

  const systemActive = status?.system_status === 'ACTIVE';

  return (
    <div className="space-y-6">
      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* System Status */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-slate-400 text-sm font-medium">System Status</h3>
            <Activity className={`w-5 h-5 ${systemActive ? 'text-green-500' : 'text-red-500'}`} />
          </div>
          <p className="text-2xl font-bold text-white">{status?.system_status || 'N/A'}</p>
          <p className={`text-xs mt-2 ${systemActive ? 'text-green-400' : 'text-red-400'}`}>
            {systemActive ? '✓ All systems operational' : '✗ System offline'}
          </p>
        </div>

        {/* XDP Status */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-slate-400 text-sm font-medium">XDP Program</h3>
            <Shield className={`w-5 h-5 ${status?.xdp_enabled ? 'text-green-500' : 'text-yellow-500'}`} />
          </div>
          <p className="text-2xl font-bold text-white">{status?.xdp_enabled ? 'Attached' : 'Detached'}</p>
          <p className={`text-xs mt-2 ${status?.xdp_enabled ? 'text-green-400' : 'text-yellow-400'}`}>
            {status?.xdp_enabled ? '✓ XDP attached' : '⚠ XDP not attached'}
          </p>
        </div>

        {/* Active Authorizations */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-slate-400 text-sm font-medium">Active IPs</h3>
            <CheckCircle className="w-5 h-5 text-blue-500" />
          </div>
          <p className="text-2xl font-bold text-white">{status?.authorized_ips_count || 0}</p>
          <p className="text-xs mt-2 text-blue-400">Currently authorized</p>
        </div>

        {/* Valid Knocks */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-slate-400 text-sm font-medium">Valid Knocks</h3>
            <Activity className="w-5 h-5 text-purple-500" />
          </div>
          <p className="text-2xl font-bold text-white">{status?.total_verified_knocks || 0}</p>
          <p className="text-xs mt-2 text-purple-400">Total verified</p>
        </div>
      </div>

      {/* Detailed Stats */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Packets Statistics */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-bold text-white mb-4">Packet Statistics</h3>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Total Packets Seen</span>
                <span className="text-white font-semibold">{stats?.packets?.total_seen || 0}</span>
              </div>
              <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                <div className="bg-blue-500 h-full" style={{width: '100%'}}></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Valid Knocks</span>
                <span className="text-green-400 font-semibold">{stats?.packets?.valid || 0}</span>
              </div>
              <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-green-500 h-full" 
                  style={{width: `${stats?.packets?.success_rate || 0}%`}}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Invalid (Rejected)</span>
                <span className="text-red-400 font-semibold">{stats?.packets?.invalid || 0}</span>
              </div>
              <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-red-500 h-full" 
                  style={{width: `${100 - (stats?.packets?.success_rate || 0)}%`}}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Replay Attacks Blocked</span>
                <span className="text-yellow-400 font-semibold">{stats?.packets?.replay_dropped || 0}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-700">
              <p className="text-slate-400 text-sm">
                Success Rate: <span className="text-green-400 font-semibold">{(stats?.packets?.success_rate || 0).toFixed(1)}%</span>
              </p>
            </div>
          </div>
        </div>

        {/* Protection Statistics */}
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
          <h3 className="text-lg font-bold text-white mb-4">Protection Statistics</h3>
          <div className="space-y-3">
            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Protected Packets Passed</span>
                <span className="text-green-400 font-semibold">{stats?.protection?.protected_passed || 0}</span>
              </div>
              <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-green-500 h-full" 
                  style={{width: `${stats?.protection?.pass_rate || 0}%`}}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Protected Packets Dropped</span>
                <span className="text-red-400 font-semibold">{stats?.protection?.protected_dropped || 0}</span>
              </div>
              <div className="bg-slate-700 h-2 rounded-full overflow-hidden">
                <div 
                  className="bg-red-500 h-full" 
                  style={{width: `${100 - (stats?.protection?.pass_rate || 0)}%`}}
                ></div>
              </div>
            </div>

            <div>
              <div className="flex justify-between mb-1">
                <span className="text-slate-300 text-sm">Protected Ports</span>
                <span className="text-blue-400 font-semibold">{stats?.protection?.protected_ports?.length || 0}</span>
              </div>
              <div className="text-xs text-slate-400 mt-2">
                Ports: <span className="text-slate-300 font-mono">{stats?.protection?.protected_ports?.join(', ') || 'None'}</span>
              </div>
            </div>

            <div className="pt-2 border-t border-slate-700">
              <p className="text-slate-400 text-sm">
                Pass Rate: <span className="text-green-400 font-semibold">{(stats?.protection?.pass_rate || 0).toFixed(1)}%</span>
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Authorization Info */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <h3 className="text-lg font-bold text-white mb-4">Authorization</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <p className="text-slate-400 text-sm mb-1">Active Authorizations</p>
            <p className="text-3xl font-bold text-blue-400">{status?.authorized_ips_count || 0}</p>
          </div>
          <div>
            <p className="text-slate-400 text-sm mb-1">Timeout</p>
            <p className="text-3xl font-bold text-slate-300">{Math.floor((stats?.authorization?.timeout_seconds || 5))} sec</p>
          </div>
          <div>
            <p className="text-slate-400 text-sm mb-1">Map Utilization</p>
            <p className="text-3xl font-bold text-slate-300">{((stats?.authorization?.active_ips || 0) / Math.max(1, stats?.authorization?.total_entries || 1) * 100).toFixed(1)}%</p>
          </div>
        </div>
      </div>
    </div>
  );
};
