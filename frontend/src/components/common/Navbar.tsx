import React, { useState, useEffect } from 'react';
import { Shield, Activity, Menu, X, ArrowUpRight, Lock, KeyRound, UserCheck, LogOut } from 'lucide-react';
import type { HealthResponse } from '../../types';
import { apiClient } from '../../services/api';
import { GlassCard } from './GlassCard';

interface NavbarProps {
  health?: HealthResponse | null;
  activeSection: string;
}

export const Navbar: React.FC<NavbarProps> = ({ health, activeSection }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [scrolled, setScrolled] = useState(false);
  const [authModalOpen, setAuthModalOpen] = useState(false);
  const [username, setUsername] = useState('operator_lead');
  const [password, setPassword] = useState('ComplexPassword123#!');
  const [authError, setAuthError] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [loggingIn, setLoggingIn] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  useEffect(() => {
    const checkUser = async () => {
      try {
        const u = await apiClient.getAuthMe();
        if (u.authenticated) {
          setCurrentUser(u);
        }
      } catch {}
    };
    checkUser();
  }, []);

  const navLinks = [
    { id: 'hero', label: '01 Core' },
    { id: 'toolkit', label: '02 Toolkit' },
    { id: 'phishing', label: '03 Phishing' },
    { id: 'apk-lab', label: '04 APK Lab' },
    { id: 'investigation', label: '05 Cases' },
    { id: 'threat-network', label: '06 3D Threat Intel' },
    { id: 'ai-lab', label: '07 AI Lab' },
    { id: 'privacy', label: '08 Privacy' },
    { id: 'health', label: '09 Health' },
    { id: 'mission', label: '10 Mission' },
  ];

  const scrollTo = (id: string) => {
    setMobileMenuOpen(false);
    const element = document.getElementById(id);
    if (element) {
      element.scrollIntoView({ behavior: 'smooth' });
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoggingIn(true);
    setAuthError(null);
    try {
      const res = await apiClient.login(username, password);
      setCurrentUser({ authenticated: true, username: res.username, role: res.role });
      setAuthModalOpen(false);
    } catch (err: any) {
      setAuthError(err.message || 'Login failed');
    } finally {
      setLoggingIn(false);
    }
  };

  const handleLogout = async () => {
    await apiClient.logout();
    setCurrentUser(null);
  };

  const isDegraded = health?.status === 'degraded';

  return (
    <>
      <header
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          scrolled ? 'liquid-glass-nav py-3' : 'bg-transparent py-5'
        }`}
      >
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex items-center justify-between">
          {/* Brand & Badge */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => scrollTo('hero')}>
            <div className="w-10 h-10 rounded-xl liquid-glass flex items-center justify-center text-[#477C78] shadow-sm">
              <Shield className="w-5 h-5 stroke-[2.2]" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-[#202C32] text-lg font-mono">
                  SEVA<span className="text-[#477C78]">//</span>CYBER
                </span>
                <span className="px-2 py-0.5 rounded-full text-[10px] font-semibold tracking-wider uppercase bg-[#DFE9E1] text-[#477C78] border border-[#477C78]/20">
                  LIQUID GLASS
                </span>
              </div>
              <p className="text-[11px] text-[#738087] tracking-wider uppercase hidden sm:block">
                Sovereign Cyber Sandbox
              </p>
            </div>
          </div>

          {/* Desktop Navigation Links */}
          <nav className="hidden lg:flex items-center gap-1 liquid-glass px-3 py-1.5 rounded-full">
            {navLinks.map((link) => {
              const isActive = activeSection === link.id;
              return (
                <button
                  key={link.id}
                  onClick={() => scrollTo(link.id)}
                  className={`px-3 py-1 text-xs font-medium rounded-full transition-all duration-200 cursor-pointer ${
                    isActive
                      ? 'bg-[#477C78] text-white shadow-xs'
                      : 'text-[#202C32] hover:text-[#477C78] hover:bg-white/40'
                  }`}
                >
                  {link.label}
                </button>
              );
            })}
          </nav>

          {/* Status Badge & Actions */}
          <div className="hidden sm:flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full liquid-glass text-xs text-[#202C32]">
              <span
                className={`w-2 h-2 rounded-full ${
                  isDegraded ? 'bg-[#C0392B] animate-pulse' : 'bg-[#477C78] animate-pulse'
                }`}
              />
              <span className="font-mono text-[11px] font-medium">
                {health?.active_model?.operating_mode ? `SHADOW AI: ${health.active_model.version.slice(0, 15)}...` : 'LOCAL ENGINE READY'}
              </span>
            </div>

            {/* Operator Auth Button */}
            {currentUser?.authenticated ? (
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-full liquid-glass text-xs text-[#202C32]">
                <UserCheck className="w-3.5 h-3.5 text-[#477C78]" />
                <span className="font-mono text-[11px] font-semibold">{currentUser.username}</span>
                <button
                  onClick={handleLogout}
                  className="p-1 hover:text-[#C0392B] cursor-pointer"
                  title="Logout"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setAuthModalOpen(true)}
                className="px-3 py-1.5 rounded-full liquid-glass hover:bg-white/60 text-[#202C32] text-xs font-medium transition-all shadow-2xs flex items-center gap-1.5 cursor-pointer"
              >
                <KeyRound className="w-3.5 h-3.5 text-[#477C78]" />
                <span>Operator Auth</span>
              </button>
            )}

            <button
              onClick={() => scrollTo('phishing')}
              className="px-4 py-1.5 rounded-full bg-[#477C78] hover:bg-[#3d6b67] text-white text-xs font-medium transition-all shadow-sm flex items-center gap-1.5 cursor-pointer"
            >
              <span>Analyze Evidence</span>
              <ArrowUpRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Mobile Menu Button */}
          <div className="lg:hidden flex items-center gap-2">
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="p-2 rounded-xl liquid-glass text-[#202C32] hover:bg-white/60 transition cursor-pointer"
              aria-label="Toggle menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {/* Mobile Drawer */}
        {mobileMenuOpen && (
          <div className="lg:hidden liquid-glass-elevated mx-4 mt-3 p-4 rounded-2xl animate-in fade-in slide-in-from-top-2 duration-200">
            <div className="grid grid-cols-2 gap-2 mb-4">
              {navLinks.map((link) => (
                <button
                  key={link.id}
                  onClick={() => scrollTo(link.id)}
                  className={`px-3 py-2 text-xs font-medium rounded-xl text-left transition ${
                    activeSection === link.id
                      ? 'bg-[#477C78] text-white'
                      : 'text-[#202C32] hover:bg-white/60'
                  }`}
                >
                  {link.label}
                </button>
              ))}
            </div>

            <div className="pt-3 border-t border-[#DDDCD3]/60 flex items-center justify-between">
              <button
                onClick={() => { setMobileMenuOpen(false); setAuthModalOpen(true); }}
                className="px-3 py-2 rounded-xl bg-[#477C78]/10 text-[#477C78] text-xs font-medium flex items-center gap-1.5"
              >
                <KeyRound className="w-4 h-4" />
                <span>Operator Login</span>
              </button>

              <button
                onClick={() => scrollTo('phishing')}
                className="px-4 py-2 rounded-xl bg-[#477C78] text-white text-xs font-medium"
              >
                Analyze Evidence
              </button>
            </div>
          </div>
        )}
      </header>

      {/* Operator Authentication Modal */}
      {authModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/40 backdrop-blur-xs animate-in fade-in">
          <div className="max-w-md w-full">
            <GlassCard className="p-6 shadow-2xl border border-soft-stone relative">
              <div className="flex items-center justify-between pb-3 mb-4 border-b border-soft-stone/60">
                <div className="flex items-center gap-2 text-deep-graphite font-bold text-sm">
                  <div className="p-1.5 rounded-lg bg-mineral-teal/10 text-mineral-teal">
                    <Lock className="w-4 h-4" />
                  </div>
                  <span>Local Operator Authentication</span>
                </div>
                <button
                  onClick={() => setAuthModalOpen(false)}
                  className="p-1 rounded text-slate-grey hover:text-deep-graphite text-xs cursor-pointer"
                >
                  &times;
                </button>
              </div>

              <p className="text-xs text-slate-grey mb-4 leading-relaxed">
                Sign in with local credentials. Passwords are protected using OWASP-compliant memory-hard scrypt (N=16384, r=8, p=5).
              </p>

              {authError && (
                <div className="mb-4 p-2.5 rounded-lg bg-red-50 border border-red-200 text-xs text-red-700">
                  {authError}
                </div>
              )}

              <form onSubmit={handleLogin} className="space-y-3">
                <div>
                  <label className="text-[11px] font-semibold text-deep-graphite block mb-1">Username</label>
                  <input
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    className="w-full text-xs font-mono p-2.5 rounded-lg border border-soft-stone bg-porcelain text-deep-graphite focus:outline-none focus:ring-1 focus:ring-mineral-teal"
                    required
                  />
                </div>

                <div>
                  <label className="text-[11px] font-semibold text-deep-graphite block mb-1">Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full text-xs font-mono p-2.5 rounded-lg border border-soft-stone bg-porcelain text-deep-graphite focus:outline-none focus:ring-1 focus:ring-mineral-teal"
                    required
                  />
                </div>

                <div className="pt-2">
                  <button
                    type="submit"
                    disabled={loggingIn}
                    className="w-full py-2.5 rounded-lg bg-mineral-teal hover:bg-mineral-teal/90 text-white text-xs font-semibold transition-all shadow-sm flex items-center justify-center gap-2 cursor-pointer disabled:opacity-50"
                  >
                    <KeyRound className="w-4 h-4" />
                    {loggingIn ? 'Authenticating (scrypt)...' : 'Sign In as Operator'}
                  </button>
                </div>
              </form>
            </GlassCard>
          </div>
        </div>
      )}
    </>
  );
};
