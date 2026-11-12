import React, { Suspense, lazy } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { DashboardLayout } from './components/layout/DashboardLayout';
import { PublicLayout } from './components/layout/PublicLayout';
import { ErrorBoundary } from './components/ui/ErrorBoundary';
import { LoadingScreen } from './components/ui/LoadingScreen';
import { AuthProvider, useAuth } from './context/AuthContext';
import { TelemetryProvider } from './context/TelemetryContext';
import { ToastProvider } from './context/ToastContext';
import { ArchitecturePage } from './pages/public/ArchitecturePage';
import { DocsPage } from './pages/public/DocsPage';
import { FeaturesPage } from './pages/public/FeaturesPage';
import { LandingPage } from './pages/public/LandingPage';
import { LoginPage } from './pages/public/LoginPage';
import { ThreatLabPage } from './pages/public/ThreatLabPage';

const OverviewPage = lazy(() =>
  import('./pages/dashboard/OverviewPage').then((m) => ({ default: m.OverviewPage }))
);
const AgentsPage = lazy(() =>
  import('./pages/dashboard/AgentsPage').then((m) => ({ default: m.AgentsPage }))
);
const MonitoringPage = lazy(() =>
  import('./pages/dashboard/MonitoringPage').then((m) => ({ default: m.MonitoringPage }))
);
const BehaviorPage = lazy(() =>
  import('./pages/dashboard/BehaviorPage').then((m) => ({ default: m.BehaviorPage }))
);
const PoliciesPage = lazy(() =>
  import('./pages/dashboard/PoliciesPage').then((m) => ({ default: m.PoliciesPage }))
);
const IncidentsPage = lazy(() =>
  import('./pages/dashboard/IncidentsPage').then((m) => ({ default: m.IncidentsPage }))
);
const AuditPage = lazy(() =>
  import('./pages/dashboard/AuditPage').then((m) => ({ default: m.AuditPage }))
);
const TestingPage = lazy(() =>
  import('./pages/dashboard/TestingPage').then((m) => ({ default: m.TestingPage }))
);
const AnalyticsPage = lazy(() =>
  import('./pages/dashboard/AnalyticsPage').then((m) => ({ default: m.AnalyticsPage }))
);
const SettingsPage = lazy(() =>
  import('./pages/dashboard/SettingsPage').then((m) => ({ default: m.SettingsPage }))
);

const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isChecking } = useAuth();
  const location = useLocation();

  if (isChecking) {
    return <LoadingScreen label="Verifying SOC session..." />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  return <>{children}</>;
};

export const App: React.FC = () => {
  return (
    <ErrorBoundary>
      <BrowserRouter>
        <ToastProvider>
          <AuthProvider>
            <TelemetryProvider>
              <Suspense fallback={<LoadingScreen />}>
                <Routes>
                  {/* Public Website Routes */}
                  <Route element={<PublicLayout />}>
                    <Route path="/" element={<LandingPage />} />
                    <Route path="/features" element={<FeaturesPage />} />
                    <Route path="/architecture" element={<ArchitecturePage />} />
                    <Route path="/threat-lab" element={<ThreatLabPage />} />
                    <Route path="/docs" element={<DocsPage />} />
                    <Route path="/login" element={<LoginPage />} />
                  </Route>

                  {/* Protected SOC Dashboard Routes */}
                  <Route
                    path="/dashboard"
                    element={
                      <ProtectedRoute>
                        <DashboardLayout />
                      </ProtectedRoute>
                    }
                  >
                    <Route index element={<OverviewPage />} />
                    <Route path="agents" element={<AgentsPage />} />
                    <Route path="monitoring" element={<MonitoringPage />} />
                    <Route path="behavior" element={<BehaviorPage />} />
                    <Route path="policies" element={<PoliciesPage />} />
                    <Route path="incidents" element={<IncidentsPage />} />
                    <Route path="audit" element={<AuditPage />} />
                    <Route path="testing" element={<TestingPage />} />
                    <Route path="analytics" element={<AnalyticsPage />} />
                    <Route path="settings" element={<SettingsPage />} />
                  </Route>

                  {/* Compatibility redirect from legacy /ui mount */}
                  <Route path="/ui" element={<Navigate to="/dashboard" replace />} />
                  <Route path="/ui/*" element={<Navigate to="/dashboard" replace />} />
                  <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
              </Suspense>
            </TelemetryProvider>
          </AuthProvider>
        </ToastProvider>
      </BrowserRouter>
    </ErrorBoundary>
  );
};
