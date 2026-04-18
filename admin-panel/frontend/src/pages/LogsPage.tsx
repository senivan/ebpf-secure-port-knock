import React, { useEffect, useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import apiClient from '../api/client';

export const LogsPage = () => {
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState<'all' | 'info' | 'warning' | 'error' | 'critical'>('all');

  useEffect(() => {
    loadEvents();
    const interval = setInterval(loadEvents, 5000);
    return () => clearInterval(interval);
  }, [filter]);

  const loadEvents = async () => {
    try {
      const data = await apiClient.getEvents(
        100,
        filter !== 'all' ? filter : undefined
      );
      setEvents(data.events || []);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to load events');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500';
      case 'error': return 'text-orange-500';
      case 'warning': return 'text-yellow-500';
      default: return 'text-blue-500';
    }
  };

  if (loading) {
    return <div className="text-center text-slate-400 py-8">Loading...</div>;
  }

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 flex gap-3">
        <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
        <p className="text-red-400">{error}</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Filter */}
      <div className="flex gap-2">
        {(['all', 'info', 'warning', 'error', 'critical'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-4 py-2 rounded-lg font-semibold transition-colors ${
              filter === f
                ? 'bg-blue-600 text-white'
                : 'bg-slate-800 text-slate-400 hover:text-white border border-slate-700'
            }`}
          >
            {f.charAt(0).toUpperCase() + f.slice(1)}
          </button>
        ))}
      </div>

      {/* Events Table */}
      <div className="bg-slate-800 border border-slate-700 rounded-lg overflow-hidden">
        {events.length === 0 ? (
          <div className="px-6 py-8 text-center text-slate-400">
            No events found
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-900/50">
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">Time</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">Severity</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">Type</th>
                  <th className="px-6 py-3 text-left text-xs font-semibold text-slate-400">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {events.map((event, idx) => (
                  <tr key={idx} className="hover:bg-slate-700/30 transition-colors">
                    <td className="px-6 py-3 text-slate-400 text-sm">
                      {new Date(event.timestamp).toLocaleString()}
                    </td>
                    <td className="px-6 py-3">
                      <span className={`font-semibold ${getSeverityColor(event.severity)}`}>
                        {event.severity.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-3 text-slate-300 text-sm font-mono">{event.type}</td>
                    <td className="px-6 py-3 text-slate-300 text-sm">{event.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
