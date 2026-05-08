import React, { createContext, useContext, useState, useEffect } from 'react';
import apiClient from '../api/client';

interface AuthContextType {
  isAuthenticated: boolean;
  user: string | null;
  loading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
  token: string | null;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider = ({ children }: { children: React.ReactNode }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    const storedToken = localStorage.getItem('auth_token');

    const restoreSession = async () => {
      if (!storedToken) {
        setLoading(false);
        return;
      }

      apiClient.setToken(storedToken);
      try {
        const response = await apiClient.verifyToken();
        if (!mounted) {
          return;
        }
        setToken(storedToken);
        setIsAuthenticated(true);
        setUser(response.user || localStorage.getItem('username'));
      } catch {
        localStorage.removeItem('auth_token');
        localStorage.removeItem('username');
        apiClient.setToken('');
        if (!mounted) {
          return;
        }
        setToken(null);
        setUser(null);
        setIsAuthenticated(false);
      } finally {
        if (mounted) {
          setLoading(false);
        }
      }
    };

    restoreSession();

    return () => {
      mounted = false;
    };
  }, []);

  const login = async (username: string, password: string) => {
    setLoading(true);
    try {
      const response = await apiClient.login(username, password);
      localStorage.setItem('auth_token', response.access_token);
      localStorage.setItem('username', response.user);
      apiClient.setToken(response.access_token);
      setToken(response.access_token);
      setUser(response.user);
      setIsAuthenticated(true);
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('username');
    apiClient.setToken('');
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, loading, login, logout, token }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
