import React, { useEffect, useState } from 'react';
import { AlertTriangle, Save, Copy } from 'lucide-react';
import apiClient from '../api/client';

export const ConfigurationPage = () => {
  const [config, setConfig] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [editing, setEditing] = useState(false);

  const [formData, setFormData] = useState({
    knock_port: '',
    protected_ports: '',
    timeout_ms: '',
    hmac_key: ''
  });

  useEffect(() => {
    loadConfig();
  }, []);

  const loadConfig = async () => {
    try {
      const data = await apiClient.getConfig();
      setConfig(data);
      setFormData({
        knock_port: data.knock_port?.toString() || '',
        protected_ports: data.protected_ports?.join(',') || '',
        timeout_ms: data.timeout_ms?.toString() || '',
        hmac_key: data.hmac_key || ''
      });
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to load config');
    } finally {
      setLoading(false);
    }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
  };

  const handleSave = async () => {
    try {
      setError('');
      setSuccess('');

      // Validate inputs
      const knockPort = parseInt(formData.knock_port);
      if (isNaN(knockPort) || knockPort < 1 || knockPort > 65535) {
        setError('Invalid knock port');
        return;
      }

      const protectedPorts = formData.protected_ports
        .split(',')
        .map(p => parseInt(p.trim()))
        .filter(p => !isNaN(p));

      const timeoutMs = parseInt(formData.timeout_ms);
      if (isNaN(timeoutMs) || timeoutMs <= 0) {
        setError('Invalid timeout');
        return;
      }

      if (formData.hmac_key.length !== 64) {
        setError('HMAC key must be 64 hex characters');
        return;
      }

      const result = await apiClient.updateConfig({
        knock_port: knockPort,
        protected_ports: protectedPorts,
        timeout_ms: timeoutMs,
        hmac_key: formData.hmac_key
      });

      setSuccess('Configuration updated successfully');
      setEditing(false);
      await loadConfig();
    } catch (err: any) {
      setError(err.response?.data?.error || 'Failed to update config');
    }
  };

  if (loading) {
    return <div className="text-center text-slate-400 py-8">Loading...</div>;
  }

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
          <div className="w-5 h-5 text-green-400 flex-shrink-0">✓</div>
          <p className="text-green-400">{success}</p>
        </div>
      )}

      {/* Configuration Form */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg p-6">
        <div className="flex justify-between items-center mb-6">
          <h3 className="text-lg font-bold text-white">System Configuration</h3>
          <button
            onClick={() => setEditing(!editing)}
            className="text-blue-400 hover:text-blue-300 font-semibold text-sm"
          >
            {editing ? 'Cancel' : 'Edit'}
          </button>
        </div>

        <div className="space-y-6">
          {/* Knock Port */}
          <div>
            <label className="block text-slate-300 text-sm font-semibold mb-2">Knock Port</label>
            <input
              type="number"
              name="knock_port"
              value={formData.knock_port}
              onChange={handleInputChange}
              disabled={!editing}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white disabled:opacity-50 focus:outline-none focus:border-blue-500"
              min="1"
              max="65535"
            />
            <p className="text-slate-400 text-xs mt-1">Port where clients send knock packets</p>
          </div>

          {/* Protected Ports */}
          <div>
            <label className="block text-slate-300 text-sm font-semibold mb-2">Protected Ports</label>
            <input
              type="text"
              name="protected_ports"
              value={formData.protected_ports}
              onChange={handleInputChange}
              disabled={!editing}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white disabled:opacity-50 focus:outline-none focus:border-blue-500"
              placeholder="e.g., 22,443,8080"
            />
            <p className="text-slate-400 text-xs mt-1">Comma-separated list of ports to protect (max 16)</p>
          </div>

          {/* Timeout */}
          <div>
            <label className="block text-slate-300 text-sm font-semibold mb-2">Timeout (milliseconds)</label>
            <input
              type="number"
              name="timeout_ms"
              value={formData.timeout_ms}
              onChange={handleInputChange}
              disabled={!editing}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white disabled:opacity-50 focus:outline-none focus:border-blue-500"
              min="1"
            />
            <p className="text-slate-400 text-xs mt-1">How long to authorize an IP after successful knock</p>
          </div>

          {/* HMAC Key */}
          <div>
            <label className="block text-slate-300 text-sm font-semibold mb-2">HMAC Key (Hex)</label>
            <textarea
              name="hmac_key"
              value={formData.hmac_key}
              onChange={handleInputChange}
              disabled={!editing}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white font-mono text-sm disabled:opacity-50 focus:outline-none focus:border-blue-500"
              rows={3}
              placeholder="64 hexadecimal characters (32 bytes)"
            />
            <p className="text-slate-400 text-xs mt-1">32-byte key as 64 hex characters. Used for signing knock packets.</p>
            {formData.hmac_key && (
              <p className="text-slate-400 text-xs mt-1">
                Length: {formData.hmac_key.length} characters ({(formData.hmac_key.length / 2).toFixed(0)} bytes)
              </p>
            )}
          </div>
        </div>

        {editing && (
          <div className="mt-6 flex gap-3">
            <button
              onClick={handleSave}
              className="bg-green-600 hover:bg-green-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors flex items-center gap-2"
            >
              <Save className="w-5 h-5" />
              Save Changes
            </button>
            <button
              onClick={() => setEditing(false)}
              className="bg-slate-600 hover:bg-slate-700 text-white font-semibold py-2 px-6 rounded-lg transition-colors"
            >
              Cancel
            </button>
          </div>
        )}
      </div>

      {/* Information Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <h4 className="text-slate-300 font-semibold mb-2">Knock Packet Format</h4>
          <p className="text-slate-400 text-sm">
            Magic: 0x4B4E4F43 | Timestamp: 4 bytes | Nonce: 4 bytes | Signature: 16 bytes
          </p>
        </div>

        <div className="bg-slate-800 border border-slate-700 rounded-lg p-4">
          <h4 className="text-slate-300 font-semibold mb-2">Clock Skew Tolerance</h4>
          <p className="text-slate-400 text-sm">
            Maximum allowed clock skew: 30 seconds (for timestamp freshness verification)
          </p>
        </div>
      </div>
    </div>
  );
};
