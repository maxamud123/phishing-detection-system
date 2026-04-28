import { useState } from 'react';
import { Shield, Mail, Lock, Eye, EyeOff, AlertCircle, UserPlus } from 'lucide-react';
import { AuthAPI } from '../lib/api';

interface LoginProps {
  onLogin: (email: string, role: string, name: string) => void;
  onSignup?: () => void;
}


export function Login({ onLogin, onSignup }: LoginProps) {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [focusedField, setFocusedField] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);
    try {
      const res = await AuthAPI.login(email.trim().toLowerCase(), password);
      if (!res.success) {
        setError(res.error || 'Invalid email or password.');
        return;
      }
      onLogin(res.user!.email, res.user!.role, res.user!.name);
    } catch {
      setError('Server unavailable. Make sure the backend is running on port 3001.');
    } finally {
      setIsLoading(false);
    }
  };

  const inputStyle = (field: string): React.CSSProperties => ({
    backgroundColor: '#1E000A',
    border: `1px solid ${focusedField === field ? 'rgba(122, 154, 184, 0.5)' : '#4A001A'}`,
    borderRadius: '12px',
    color: 'white',
    fontSize: '14px',
    outline: 'none',
    width: '100%',
    padding: '11px 16px',
    transition: 'border-color 0.2s',
    boxShadow: focusedField === field ? '0 0 0 3px rgba(122, 154, 184, 0.08)' : 'none',
  });

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{
        backgroundColor: '#3A0015',
        fontFamily: "'Inter', sans-serif",
        backgroundImage:
          'linear-gradient(rgba(122, 154, 184, 0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(122, 154, 184, 0.025) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
      }}
    >
      {/* Glow blobs */}
      <div
        className="fixed pointer-events-none"
        style={{
          width: '600px',
          height: '600px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(122, 154, 184,0.06) 0%, transparent 70%)',
          top: '-100px',
          left: '-100px',
        }}
      />
      <div
        className="fixed pointer-events-none"
        style={{
          width: '400px',
          height: '400px',
          borderRadius: '50%',
          background: 'radial-gradient(circle, rgba(90, 128, 168,0.05) 0%, transparent 70%)',
          bottom: '0px',
          right: '0px',
        }}
      />

      <div className="w-full max-w-md relative">
        {/* Logo / Header */}
        <div className="text-center mb-8">
          <div
            className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4"
            style={{
              background: 'linear-gradient(135deg, rgba(122, 154, 184,0.15), rgba(122, 154, 184,0.3))',
              border: '1px solid rgba(122, 154, 184, 0.4)',
              boxShadow: '0 0 40px rgba(122, 154, 184, 0.25)',
            }}
          >
            <Shield className="w-8 h-8" style={{ color: '#7A9AB8' }} />
          </div>
          <h1 style={{ fontSize: '26px', fontWeight: 800, color: 'white', letterSpacing: '-0.02em' }}>
            Phish Guard
          </h1>
          <p style={{ fontSize: '13px', color: '#3A5A7A', marginTop: '4px' }}>
            Cyber Threat Detection Platform
          </p>
        </div>

        {/* Card */}
        <div
          className="rounded-2xl p-8"
          style={{
            backgroundColor: '#2A0010',
            border: '1px solid #4A001A',
            boxShadow: '0 0 60px rgba(0,0,0,0.5), 0 0 40px rgba(122, 154, 184,0.04)',
          }}
        >
          {/* Colored top border */}
          <div
            className="absolute top-0 left-0 right-0 h-0.5 rounded-t-2xl"
            style={{ background: 'linear-gradient(90deg, transparent, #7A9AB8, transparent)' }}
          />

          <div className="flex items-start justify-between mb-6">
            <div>
              <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'white', marginBottom: '4px' }}>Sign In</h2>
              <p style={{ fontSize: '13px', color: '#3A5A7A' }}>Access your security dashboard</p>
            </div>
            {onSignup && (
              <button onClick={onSignup} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg transition-all hover:bg-white/5"
                style={{ fontSize:'12px', color:'#7A9AB8', border:'1px solid rgba(122, 154, 184,0.2)', fontWeight:600 }}>
                <UserPlus className="w-3.5 h-3.5" /> Sign Up
              </button>
            )}
          </div>

          {error && (
            <div
              className="flex items-center gap-2 px-4 py-3 rounded-xl mb-5"
              style={{
                backgroundColor: 'rgba(239, 68, 68, 0.08)',
                border: '1px solid rgba(239, 68, 68, 0.25)',
              }}
            >
              <AlertCircle className="w-4 h-4 shrink-0" style={{ color: '#ef4444' }} />
              <p style={{ fontSize: '13px', color: '#ef4444' }}>{error}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label
                style={{
                  fontSize: '11px',
                  color: '#5A80A8',
                  display: 'block',
                  marginBottom: '8px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  fontWeight: 600,
                }}
              >
                Email Address
              </label>
              <div className="relative">
                <Mail
                  className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none"
                  style={{ color: focusedField === 'email' ? '#7A9AB8' : '#3A5A7A' }}
                />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  onFocus={() => setFocusedField('email')}
                  onBlur={() => setFocusedField(null)}
                  placeholder="your@email.com"
                  style={{ ...inputStyle('email'), paddingLeft: '44px' }}
                  required
                />
              </div>
            </div>

            <div>
              <label
                style={{
                  fontSize: '11px',
                  color: '#5A80A8',
                  display: 'block',
                  marginBottom: '8px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  fontWeight: 600,
                }}
              >
                Password
              </label>
              <div className="relative">
                <Lock
                  className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none"
                  style={{ color: focusedField === 'password' ? '#7A9AB8' : '#3A5A7A' }}
                />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onFocus={() => setFocusedField('password')}
                  onBlur={() => setFocusedField(null)}
                  placeholder="Enter your password"
                  style={{ ...inputStyle('password'), paddingLeft: '44px', paddingRight: '44px' }}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-4 top-1/2 -translate-y-1/2 transition-colors"
                  style={{ color: showPassword ? '#7A9AB8' : '#3A5A7A' }}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full py-3 rounded-xl transition-all duration-200 mt-2 relative overflow-hidden"
              style={{
                background: isLoading
                  ? 'rgba(122, 154, 184, 0.4)'
                  : 'linear-gradient(135deg, #7A9AB8, #0099bb)',
                color: '#3A0015',
                fontWeight: 700,
                fontSize: '14px',
                boxShadow: isLoading ? 'none' : '0 0 24px rgba(122, 154, 184, 0.3)',
                cursor: isLoading ? 'not-allowed' : 'pointer',
              }}
            >
              {isLoading ? (
                <span className="flex items-center justify-center gap-2">
                  <span
                    className="w-4 h-4 rounded-full border-2 border-current border-t-transparent animate-spin inline-block"
                  />
                  Authenticating...
                </span>
              ) : (
                'Sign In'
              )}
            </button>
          </form>
        </div>

      </div>
    </div>
  );
}
