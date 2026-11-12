import React, { useState } from 'react';
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom';
import { ArrowRight, ExternalLink, Menu, ShieldCheck, X } from 'lucide-react';
import { CerberusLogo } from '../brand/CerberusLogo';
import { Button } from '../ui/Button';

const NAV_ITEMS = [
  { to: '/', label: 'Home', end: true },
  { to: '/features', label: 'Features' },
  { to: '/architecture', label: 'Architecture' },
  { to: '/threat-lab', label: 'Threat Lab' },
  { to: '/docs', label: 'Docs' },
];

export const PublicLayout: React.FC = () => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex flex-col bg-[#F3F0FF] text-[#171638]">
      <header className="sticky top-0 z-40 bg-white/85 backdrop-blur-md border-b border-[#E3DDF8]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between gap-4">
          <Link to="/" className="flex items-center gap-2.5 group shrink-0">
            <CerberusLogo size={38} showHalo={false} className="transition-transform group-hover:scale-105" />
            <div>
              <span className="font-display font-extrabold text-lg tracking-tight text-[#171638]">
                CERBERUS
              </span>
              <span className="hidden sm:inline-block ml-2 px-2 py-0.5 text-[10px] font-mono font-semibold rounded-full bg-[#EAE6FF] text-[#6654E8] border border-[#DCD5FF]">
                MCP FIREWALL
              </span>
            </div>
          </Link>

          <nav className="hidden md:flex items-center gap-1" aria-label="Public navigation">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                className={({ isActive }) =>
                  `px-3.5 py-2 rounded-xl text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-[#EAE6FF] text-[#6654E8] font-semibold'
                      : 'text-[#666581] hover:text-[#171638] hover:bg-[#F3F0FF]'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
            <a
              href="https://github.com/Debddj/Cerberus"
              target="_blank"
              rel="noreferrer"
              className="px-3.5 py-2 rounded-xl text-sm font-medium text-[#666581] hover:text-[#171638] hover:bg-[#F3F0FF] inline-flex items-center gap-1"
            >
              GitHub
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </nav>

          <div className="hidden md:flex items-center gap-2.5">
            <Button variant="ghost" size="sm" onClick={() => navigate('/login')}>
              SOC Login
            </Button>
            <Button size="sm" onClick={() => navigate('/dashboard')}>
              Get Started
              <ArrowRight className="w-3.5 h-3.5" />
            </Button>
          </div>

          <button
            onClick={() => setMobileOpen((v) => !v)}
            className="md:hidden p-2 rounded-xl bg-[#F3F0FF] border border-[#E3DDF8] text-[#171638]"
            aria-label="Toggle mobile navigation"
          >
            {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </button>
        </div>

        {mobileOpen && (
          <div className="md:hidden bg-white border-t border-[#E3DDF8] px-4 py-4 space-y-2">
            {NAV_ITEMS.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={() => setMobileOpen(false)}
                className={({ isActive }) =>
                  `block px-3.5 py-2.5 rounded-xl text-sm font-medium ${
                    isActive ? 'bg-[#EAE6FF] text-[#6654E8] font-semibold' : 'text-[#666581]'
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
            <a
              href="https://github.com/Debddj/Cerberus"
              target="_blank"
              rel="noreferrer"
              className="flex items-center justify-between px-3.5 py-2.5 rounded-xl text-sm font-medium text-[#666581]"
            >
              GitHub Repository
              <ExternalLink className="w-4 h-4" />
            </a>
            <div className="pt-2 flex gap-2">
              <Button
                variant="outline"
                className="flex-1"
                onClick={() => {
                  setMobileOpen(false);
                  navigate('/login');
                }}
              >
                SOC Login
              </Button>
              <Button
                className="flex-1"
                onClick={() => {
                  setMobileOpen(false);
                  navigate('/dashboard');
                }}
              >
                Get Started
              </Button>
            </div>
          </div>
        )}
      </header>

      <main className="flex-1">
        <Outlet />
      </main>

      <footer className="bg-white border-t border-[#E3DDF8] mt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="md:col-span-2 space-y-3">
              <div className="flex items-center gap-2.5">
                <CerberusLogo size={36} showHalo={false} />
                <div>
                  <span className="font-display font-extrabold text-base text-[#171638]">
                    CERBERUS
                  </span>
                  <p className="text-xs text-[#6654E8] font-semibold tracking-wide">
                    WATCH. ANALYZE. PROTECT.
                  </p>
                </div>
              </div>
              <p className="text-sm text-[#666581] max-w-md leading-relaxed">
                Runtime Behavioral Firewall &amp; Zero-Trust Control Plane for MCP-Based Autonomous
                AI Agents. Observe, Analyze, Enforce, Investigate, and Adapt across every tool
                trajectory.
              </p>
              <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#F3F0FF] border border-[#E3DDF8] text-xs font-medium text-[#6654E8]">
                <ShieldCheck className="w-3.5 h-3.5" />
                Apache-2.0 Open Source Security Research &amp; Engineering Platform
              </div>
            </div>

            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#171638] mb-3">
                Platform
              </h4>
              <ul className="space-y-2 text-sm text-[#666581]">
                <li>
                  <Link to="/features" className="hover:text-[#6654E8]">
                    Security Features
                  </Link>
                </li>
                <li>
                  <Link to="/architecture" className="hover:text-[#6654E8]">
                    System Architecture
                  </Link>
                </li>
                <li>
                  <Link to="/threat-lab" className="hover:text-[#6654E8]">
                    Interactive Threat Lab
                  </Link>
                </li>
                <li>
                  <Link to="/dashboard" className="hover:text-[#6654E8]">
                    SOC Control Plane
                  </Link>
                </li>
              </ul>
            </div>

            <div>
              <h4 className="text-xs font-bold uppercase tracking-wider text-[#171638] mb-3">
                Resources
              </h4>
              <ul className="space-y-2 text-sm text-[#666581]">
                <li>
                  <Link to="/docs" className="hover:text-[#6654E8]">
                    Documentation
                  </Link>
                </li>
                <li>
                  <Link to="/docs#api-reference" className="hover:text-[#6654E8]">
                    REST &amp; MCP API Reference
                  </Link>
                </li>
                <li>
                  <a
                    href="https://github.com/Debddj/Cerberus"
                    target="_blank"
                    rel="noreferrer"
                    className="hover:text-[#6654E8] inline-flex items-center gap-1"
                  >
                    GitHub Repository
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </li>
                <li>
                  <Link to="/login" className="hover:text-[#6654E8]">
                    Operator Sign In
                  </Link>
                </li>
              </ul>
            </div>
          </div>

          <div className="mt-10 pt-6 border-t border-[#E3DDF8] flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-[#666581]">
            <p>© {new Date().getFullYear()} CERBERUS Security Platform. All rights reserved.</p>
            <p className="font-mono">
              Dual Transport: HTTP JSON-RPC Gateway &amp; MCP Stdio Subprocess Proxy
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

