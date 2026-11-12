import React, { useMemo, useState } from 'react';
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import {
  Activity,
  AlertOctagon,
  BarChart3,
  Bell,
  Bot,
  BrainCircuit,
  ChevronRight,
  FileCheck2,
  FlaskConical,
  Home,
  LayoutDashboard,
  LogOut,
  Menu,
  PanelLeftClose,
  PanelLeftOpen,
  Radio,
  RefreshCw,
  Settings,
  ShieldCheck,
  UserCheck,
  X,
} from 'lucide-react';
import { CerberusLogo } from '../brand/CerberusLogo';
import { useAuth } from '../../context/AuthContext';
import { useTelemetry } from '../../context/TelemetryContext';
import { Badge, decisionTone, formatDecisionLabel } from '../ui/Badge';
import { StatusBanner } from '../ui/StatusBanner';

const SIDEBAR_LINKS = [
  { to: '/dashboard', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/dashboard/agents', label: 'Agents', icon: Bot },
  { to: '/dashboard/monitoring', label: 'Live Monitoring', icon: Activity },
  { to: '/dashboard/behavior', label: 'Behavioural Intelligence', icon: BrainCircuit },
  { to: '/dashboard/policies', label: 'Policy Management', icon: ShieldCheck },
  { to: '/dashboard/incidents', label: 'Incidents', icon: AlertOctagon },
  { to: '/dashboard/audit', label: 'Audit & Integrity', icon: FileCheck2 },
  { to: '/dashboard/testing', label: 'Testing & Simulation', icon: FlaskConical },
  { to: '/dashboard/analytics', label: 'Performance Analytics', icon: BarChart3 },
  { to: '/dashboard/settings', label: 'Settings', icon: Settings },
];

export const DashboardLayout: React.FC = () => {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileDrawer, setMobileDrawer] = useState(false);
  const [showAlerts, setShowAlerts] = useState(false);
  const [showProfile, setShowProfile] = useState(false);

  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, authMode } = useAuth();
  const { metrics, events, connectionSource, isStreaming, loading, refreshAll } = useTelemetry();

  const currentNav = useMemo(() => {
    return (
      SIDEBAR_LINKS.find((item) =>
        item.end ? location.pathname === item.to : location.pathname.startsWith(item.to)
      ) || SIDEBAR_LINKS[0]
    );
  }, [location.pathname]);

  const alertEvents = useMemo(
    () =>
      events
        .filter((e) => e.decision === 'block' || e.decision === 'quarantine' || e.decision === 'flag')
        .slice(0, 6),
    [events]
  );

  const renderNavItems = (onNavigate?: () => void) => (
    <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto" aria-label="SOC Sidebar">
      {SIDEBAR_LINKS.map((item) => {
        const Icon = item.icon;
        return (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            onClick={onNavigate}
            title={collapsed ? item.label : undefined}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-sm font-medium transition-all ${
                isActive
                  ? 'cerberus-gradient-btn text-white font-semibold'
                  : 'text-[#666581] hover:text-[#171638] hover:bg-white/75'
              }`
            }
          >
            {({ isActive }) => (
              <>
                <Icon
                  className={`w-4 h-4 shrink-0 ${isActive ? 'text-white' : 'text-[#6654E8]'}`}
                />
                {!collapsed && <span className="truncate">{item.label}</span>}
              </>
            )}
          </NavLink>
        );
      })}
    </nav>
  );

  return (
    <div className="min-h-screen flex bg-[#F3F0FF] text-[#171638]">
      {/* Desktop Persistent Lavender Sidebar */}
      <aside
        className={`hidden lg:flex flex-col shrink-0 bg-[#EAE6FF] border-r border-[#E3DDF8] transition-all duration-200 sticky top-0 h-screen ${
          collapsed ? 'w-[78px]' : 'w-64'
        }`}
      >
        <div className="h-16 px-4 border-b border-[#E3DDF8] flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2.5 min-w-0">
            <CerberusLogo size={34} showHalo={false} className="shrink-0" />
            {!collapsed && (
              <div className="min-w-0">
                <span className="font-display font-extrabold text-base tracking-tight text-[#171638] block leading-none">
                  CERBERUS
                </span>
                <span className="text-[10px] font-mono text-[#6654E8] font-semibold uppercase tracking-wider">
                  SOC Control Plane
                </span>
              </div>
            )}
          </Link>
          <button
            onClick={() => setCollapsed((c) => !c)}
            className="p-1.5 rounded-lg hover:bg-white/70 text-[#666581] hover:text-[#171638]"
            aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {collapsed ? (
              <PanelLeftOpen className="w-4 h-4" />
            ) : (
              <PanelLeftClose className="w-4 h-4" />
            )}
          </button>
        </div>

        {renderNavItems()}

        <div className="p-3 border-t border-[#E3DDF8]">
          {!collapsed ? (
            <div className="bg-white/80 rounded-xl p-3 border border-[#E3DDF8] space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-[#171638]">Enforcement</span>
                <Badge tone={metrics?.fail_closed !== false ? 'success' : 'warning'} dot>
                  {metrics?.fail_closed !== false ? 'Fail-Closed' : 'Fail-Open'}
                </Badge>
              </div>
              <Link
                to="/"
                className="flex items-center justify-between text-xs text-[#6654E8] hover:underline font-medium pt-1"
              >
                <span>Public Website</span>
                <Home className="w-3.5 h-3.5" />
              </Link>
            </div>
          ) : (
            <Link
              to="/"
              title="Public Website"
              className="flex items-center justify-center p-2.5 rounded-xl bg-white/80 border border-[#E3DDF8] text-[#6654E8]"
            >
              <Home className="w-4 h-4" />
            </Link>
          )}
        </div>
      </aside>

      {/* Mobile Slide-Over Sidebar */}
      {mobileDrawer && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-[#171638]/35 backdrop-blur-[1px]"
            onClick={() => setMobileDrawer(false)}
          />
          <aside className="relative z-10 w-72 bg-[#EAE6FF] border-r border-[#E3DDF8] h-full flex flex-col">
            <div className="h-16 px-4 border-b border-[#E3DDF8] flex items-center justify-between">
              <Link to="/" className="flex items-center gap-2.5">
                <CerberusLogo size={34} showHalo={false} />
                <span className="font-display font-extrabold text-base text-[#171638]">
                  CERBERUS
                </span>
              </Link>
              <button
                onClick={() => setMobileDrawer(false)}
                className="p-1.5 rounded-lg bg-white/80 text-[#666581]"
                aria-label="Close navigation menu"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
            {renderNavItems(() => setMobileDrawer(false))}
          </aside>
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 min-w-0 flex flex-col">
        <header className="sticky top-0 z-30 h-16 bg-white/90 backdrop-blur border-b border-[#E3DDF8] px-4 sm:px-6 flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            <button
              onClick={() => setMobileDrawer(true)}
              className="lg:hidden p-2 rounded-xl bg-[#F3F0FF] border border-[#E3DDF8] text-[#171638]"
              aria-label="Open navigation menu"
            >
              <Menu className="w-5 h-5" />
            </button>

            <nav aria-label="Breadcrumb" className="flex items-center gap-1.5 text-xs sm:text-sm min-w-0">
              <Link to="/dashboard" className="text-[#666581] hover:text-[#6654E8] font-medium">
                CERBERUS SOC
              </Link>
              <ChevronRight className="w-4 h-4 text-[#A29DC4] shrink-0" />
              <span className="font-bold text-[#171638] truncate">{currentNav.label}</span>
            </nav>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <Badge
              tone={connectionSource === 'live' ? (isStreaming ? 'success' : 'primary') : 'warning'}
              dot
            >
              <Radio className="w-3 h-3" />
              <span className="hidden sm:inline">
                {connectionSource === 'live'
                  ? isStreaming
                    ? 'SSE Live'
                    : 'API Connected'
                  : 'Offline Demo'}
              </span>
            </Badge>

            <button
              onClick={refreshAll}
              disabled={loading}
              className="p-2 rounded-xl bg-[#F3F0FF] hover:bg-[#EAE6FF] border border-[#E3DDF8] text-[#6654E8] transition-colors"
              title="Refresh live telemetry"
              aria-label="Refresh telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>

            {/* Notifications Indicator */}
            <div className="relative">
              <button
                onClick={() => {
                  setShowAlerts((v) => !v);
                  setShowProfile(false);
                }}
                className="relative p-2 rounded-xl bg-[#F3F0FF] hover:bg-[#EAE6FF] border border-[#E3DDF8] text-[#171638]"
                aria-label="Security notifications"
              >
                <Bell className="w-4 h-4" />
                {alertEvents.length > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-[#F06478] text-white text-[10px] font-bold flex items-center justify-center">
                    {alertEvents.length}
                  </span>
                )}
              </button>

              {showAlerts && (
                <div className="absolute right-0 mt-2 w-80 bg-white border border-[#E3DDF8] rounded-2xl shadow-card-hover p-3 z-50">
                  <div className="flex items-center justify-between px-2 pb-2 border-b border-[#E3DDF8]">
                    <span className="text-xs font-bold text-[#171638]">Recent Security Alerts</span>
                    <button
                      onClick={() => {
                        setShowAlerts(false);
                        navigate('/dashboard/incidents');
                      }}
                      className="text-[11px] font-semibold text-[#6654E8] hover:underline"
                    >
                      View Incidents
                    </button>
                  </div>
                  <div className="divide-y divide-[#F3F0FF] max-h-64 overflow-y-auto mt-1">
                    {alertEvents.length === 0 ? (
                      <p className="py-6 text-center text-xs text-[#666581]">
                        No flagged or blocked alerts yet.
                      </p>
                    ) : (
                      alertEvents.map((ev) => (
                        <button
                          key={ev.event_id}
                          onClick={() => {
                            setShowAlerts(false);
                            navigate('/dashboard/monitoring');
                          }}
                          className="w-full text-left px-2 py-2.5 hover:bg-[#F3F0FF] rounded-xl flex items-center justify-between gap-2"
                        >
                          <div className="min-w-0">
                            <p className="text-xs font-mono font-semibold text-[#171638] truncate">
                              {ev.tool_name}
                            </p>
                            <p className="text-[11px] text-[#666581] truncate">{ev.agent_id}</p>
                          </div>
                          <Badge tone={decisionTone(ev.decision)}>
                            {formatDecisionLabel(ev.decision)}
                          </Badge>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* User Profile */}
            <div className="relative">
              <button
                onClick={() => {
                  setShowProfile((v) => !v);
                  setShowAlerts(false);
                }}
                className="flex items-center gap-2 pl-2 pr-3 py-1.5 rounded-xl bg-[#F3F0FF] hover:bg-[#EAE6FF] border border-[#E3DDF8]"
              >
                <div className="w-6 h-6 rounded-lg cerberus-gradient-btn flex items-center justify-center text-white text-xs font-bold">
                  {(user?.username || 'A')[0].toUpperCase()}
                </div>
                <span className="hidden md:inline text-xs font-semibold text-[#171638]">
                  {user?.username || 'admin'}
                </span>
              </button>

              {showProfile && (
                <div className="absolute right-0 mt-2 w-60 bg-white border border-[#E3DDF8] rounded-2xl shadow-card-hover p-2 z-50">
                  <div className="px-3 py-2 border-b border-[#E3DDF8]">
                    <p className="text-xs font-bold text-[#171638]">{user?.display_name}</p>
                    <p className="text-[11px] text-[#666581] flex items-center gap-1 mt-0.5">
                      <UserCheck className="w-3 h-3 text-[#22B982]" />
                      {user?.role} ({authMode === 'live' ? 'Backend Auth' : 'Offline Preview'})
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      setShowProfile(false);
                      navigate('/dashboard/settings');
                    }}
                    className="w-full text-left px-3 py-2 mt-1 rounded-xl text-xs font-medium text-[#171638] hover:bg-[#F3F0FF] flex items-center gap-2"
                  >
                    <Settings className="w-3.5 h-3.5 text-[#6654E8]" />
                    Platform Settings
                  </button>
                  <button
                    onClick={() => {
                      setShowProfile(false);
                      logout();
                      navigate('/login');
                    }}
                    className="w-full text-left px-3 py-2 rounded-xl text-xs font-medium text-[#C6384D] hover:bg-[#F06478]/10 flex items-center gap-2"
                  >
                    <LogOut className="w-3.5 h-3.5" />
                    Sign Out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-[1440px] w-full mx-auto space-y-6">
          <StatusBanner source={connectionSource} onRetry={refreshAll} />
          <Outlet />
        </main>
      </div>
    </div>
  );
};

