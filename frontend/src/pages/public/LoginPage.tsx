import React, { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ArrowRight, Lock, ShieldCheck, User } from 'lucide-react';
import { CerberusLogo } from '../../components/brand/CerberusLogo';
import { MountainBackdrop } from '../../components/brand/MountainBackdrop';
import { Button } from '../../components/ui/Button';
import { useAuth } from '../../context/AuthContext';
import { useToast } from '../../context/ToastContext';

export const LoginPage: React.FC = () => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('cerberus-soc');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { login } = useAuth();
  const { addToast } = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const fromPath =
    (location.state as { from?: { pathname?: string } } | null)?.from?.pathname || '/dashboard';

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const mode = await login(username, password);
      addToast({
        title: 'Authenticated to CERBERUS SOC',
        description:
          mode === 'live'
            ? 'Verified HMAC session token issued by FastAPI backend.'
            : 'Backend offline — entered local preview mode.',
        variant: mode === 'live' ? 'success' : 'warning',
      });
      navigate(fromPath, { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="relative min-h-[calc(100vh-4rem)] cerberus-hero-surface flex items-center justify-center p-4 overflow-hidden">
      <MountainBackdrop className="absolute bottom-0 left-0 right-0 w-full h-64 opacity-85" />

      <div className="relative z-10 w-full max-w-md bg-white/95 backdrop-blur border border-[#E3DDF8] rounded-3xl shadow-card-hover p-8 space-y-6">
        <div className="flex flex-col items-center text-center space-y-2">
          <CerberusLogo size={84} showHalo />
          <h1 className="font-display text-2xl font-extrabold text-[#171638]">CERBERUS SOC</h1>
          <p className="text-xs text-[#666581]">
            Sign in to access the Security Operations Center &amp; Policy Control Plane
          </p>
        </div>

        {error && (
          <div className="p-3 rounded-xl bg-[#F06478]/12 border border-[#F06478]/30 text-xs font-medium text-[#C6384D]">
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="soc-user" className="text-xs font-semibold text-[#171638] block">
              Operator Username
            </label>
            <div className="relative">
              <User className="w-4 h-4 text-[#8C7BFA] absolute left-3.5 top-3" />
              <input
                id="soc-user"
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-sm text-[#171638] focus:outline-none focus:border-[#6654E8]"
                placeholder="admin"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <label htmlFor="soc-pass" className="text-xs font-semibold text-[#171638] block">
              Access Passphrase
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 text-[#8C7BFA] absolute left-3.5 top-3" />
              <input
                id="soc-pass"
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-[#FAF8FF] border border-[#E3DDF8] text-sm text-[#171638] focus:outline-none focus:border-[#6654E8]"
                placeholder="••••••••••••"
              />
            </div>
          </div>

          <Button type="submit" disabled={submitting} className="w-full py-2.5">
            {submitting ? 'Verifying Session...' : 'Enter Security Operations Center'}
            <ArrowRight className="w-4 h-4" />
          </Button>
        </form>

        <div className="rounded-xl bg-[#F3F0FF] border border-[#E3DDF8] p-3.5 text-xs text-[#666581] space-y-1">
          <div className="flex items-center gap-1.5 font-semibold text-[#171638]">
            <ShieldCheck className="w-3.5 h-3.5 text-[#6654E8]" />
            Local Development Credentials
          </div>
          <p className="font-mono text-[11px]">
            Username: <strong>admin</strong> · Passphrase: <strong>cerberus-soc</strong>
          </p>
          <p className="text-[11px]">
            Override in production via <code className="text-[#6654E8]">CERBERUS_SOC_USERNAME</code>{' '}
            and <code className="text-[#6654E8]">CERBERUS_SOC_PASSWORD</code>.
          </p>
        </div>
      </div>
    </div>
  );
};

