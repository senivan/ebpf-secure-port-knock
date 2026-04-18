import React, { useState } from 'react';
import { Menu, X, LogOut, BarChart3, Settings, Lock, AlertCircle, FileText } from 'lucide-react';
import { useAuth } from './contexts/AuthContext';
import { LoginPage } from './pages/LoginPage';
import { Dashboard } from './pages/Dashboard';
import { ConfigurationPage } from './pages/ConfigurationPage';
import { AuthorizedIPsPage } from './pages/AuthorizedIPsPage';
import { TestingPage } from './pages/TestingPage';
import { LogsPage } from './pages/LogsPage';

interface NavItem {
  id: string;
  label: string;
  icon: any;
}

const navItems: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
  { id: 'ips', label: 'Authorized IPs', icon: Lock },
  { id: 'config', label: 'Configuration', icon: Settings },
  { id: 'test', label: 'Testing', icon: AlertCircle },
  { id: 'logs', label: 'Logs', icon: FileText },
];

function App() {
  const { isAuthenticated, user, loading: authLoading, logout } = useAuth();
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);

  if (authLoading) {
    return (
      <div className="min-h-screen bg-slate-900 flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-slate-400">Loading...</p>
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginPage />;
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard': return <Dashboard />;
      case 'ips': return <AuthorizedIPsPage />;
      case 'config': return <ConfigurationPage />;
      case 'test': return <TestingPage />;
      case 'logs': return <LogsPage />;
      default: return <Dashboard />;
    }
  };

  const currentNav = navItems.find(item => item.id === currentPage);

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-800 text-white">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden text-slate-400 hover:text-white transition-colors"
            >
              {sidebarOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
            <div>
              <h1 className="text-2xl font-bold">eBPF Knock Admin</h1>
              <p className="text-slate-400 text-xs">Secure Port Knock Management</p>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="text-sm">
              <p className="text-slate-400">Logged in as</p>
              <p className="font-semibold">{user}</p>
            </div>
            <button
              onClick={logout}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 rounded-lg transition-colors"
            >
              <LogOut className="w-4 h-4" />
              Logout
            </button>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside
          className={`absolute lg:sticky top-14 left-0 right-0 bottom-0 w-64 bg-slate-900 border-r border-slate-700 transform transition-transform lg:translate-x-0 ${
            sidebarOpen ? 'translate-x-0' : '-translate-x-full'
          } z-40 lg:z-0`}
        >
          <nav className="p-4 space-y-2">
            {navItems.map(item => {
              const Icon = item.icon;
              return (
                <button
                  key={item.id}
                  onClick={() => {
                    setCurrentPage(item.id);
                    setSidebarOpen(false);
                  }}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-all ${
                    currentPage === item.id
                      ? 'bg-blue-600 text-white'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="font-semibold">{item.label}</span>
                </button>
              );
            })}
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-4 lg:p-8 overflow-auto">
          <div className="max-w-6xl mx-auto">
            {/* Page Header */}
            <div className="mb-8">
              <div className="flex items-center gap-2 mb-2">
                {currentNav && <currentNav.icon className="w-6 h-6 text-blue-500" />}
                <h2 className="text-3xl font-bold">{currentNav?.label || 'Dashboard'}</h2>
              </div>
              <p className="text-slate-400">Manage your eBPF secure port knock system</p>
            </div>

            {/* Page Content */}
            <div className="animate-fadeIn">
              {renderPage()}
            </div>
          </div>
        </main>
      </div>

      {/* Overlay for mobile sidebar */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-30 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}
    </div>
  );
}

export default App;
