import React, { createContext, useCallback, useContext, useEffect, useState } from 'react';
import { checkSocSession, loginSoc } from '../services/api';
import type { SocUser } from '../types';

interface AuthContextValue {
  isAuthenticated: boolean;
  isChecking: boolean;
  user: SocUser | null;
  authMode: 'live' | 'offline-demo';
  login: (username: string, password: string) => Promise<'live' | 'offline-demo'>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<SocUser | null>(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isChecking, setIsChecking] = useState(true);
  const [authMode, setAuthMode] = useState<'live' | 'offline-demo'>('live');

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await checkSocSession();
        if (!active) return;
        if (res.authenticated && res.user) {
          setUser(res.user);
          setIsAuthenticated(true);
          const token = localStorage.getItem('cerberus_soc_token');
          setAuthMode(token === 'offline-demo-token' ? 'offline-demo' : 'live');
        }
      } finally {
        if (active) setIsChecking(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const login = useCallback(async (username: string, password: string) => {
    const res = await loginSoc(username, password);
    localStorage.setItem('cerberus_soc_token', res.token);
    setUser(res.user);
    setIsAuthenticated(true);
    setAuthMode(res.source);
    return res.source;
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('cerberus_soc_token');
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  return (
    <AuthContext.Provider value={{ isAuthenticated, isChecking, user, authMode, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

