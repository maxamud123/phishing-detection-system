import { useState } from 'react';
import { Shield, User, Mail, Lock, Eye, EyeOff, AlertCircle, CheckCircle } from 'lucide-react';
import { AuthAPI } from '../lib/api';

interface SignupProps {
  onSuccess: () => void;
  onBackToLogin: () => void;
  isAdminCreating?: boolean; // true when admin is adding a user from admin panel
}


export function Signup({ onSuccess, onBackToLogin, isAdminCreating = false }: SignupProps) {
  const [form, setForm] = useState({ name: '', email: '', password: '', confirmPassword: '' });
  const [showPwd, setShowPwd] = useState(false);
  const [showCfm, setShowCfm] = useState(false);
  const [focused, setFocused] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');
  const [success, setSuccess] = useState('');

  const strength = (() => {
    const p = form.password;
    if (!p) return 0;
    let s = 0;
    if (p.length >= 8)          s++;
    if (/[A-Z]/.test(p))        s++;
    if (/[0-9]/.test(p))        s++;
    if (/[^A-Za-z0-9]/.test(p)) s++;
    return s;
  })();
  const strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][strength];
  const strengthColor = ['', '#ef4444', '#f59e0b', '#22c55e', '#00d4ff'][strength];

  const inputStyle = (field: string): React.CSSProperties => ({
    backgroundColor: '#060b18',
    border: `1px solid ${focused === field ? 'rgba(0, 212, 255, 0.5)' : '#1a2040'}`,
    borderRadius: '12px', color: 'white', fontSize: '14px', outline: 'none',
    width: '100%', padding: '11px 16px', transition: 'border-color 0.2s',
    boxShadow: focused === field ? '0 0 0 3px rgba(0, 212, 255, 0.08)' : 'none',
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(''); setSuccess('');
    if (!form.name.trim()) return setError('Full name is required.');
    if (form.password !== form.confirmPassword) return setError('Passwords do not match.');
    if (form.password.length < 6) return setError('Password must be at least 6 characters.');

    setLoading(true);
    try {
      const res = await AuthAPI.signup({
        name:            form.name.trim(),
        email:           form.email.trim(),
        password:        form.password,
        confirmPassword: form.confirmPassword,
      });
      if (!res.success) { setError(res.error || 'Signup failed.'); return; }
      setSuccess(isAdminCreating
        ? `User "${form.name}" created successfully!`
        : 'Account created! Redirecting to login…'
      );
      setTimeout(() => {
        if (isAdminCreating) { onSuccess(); }
        else                 { onBackToLogin(); }
      }, 1500);
    } catch {
      setError('Server unavailable. Make sure the backend is running on port 3001.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{
        backgroundColor: '#0a0e1a', fontFamily: "'Inter', sans-serif",
        backgroundImage: 'linear-gradient(rgba(0, 212, 255, 0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(0, 212, 255, 0.025) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
      }}
    >
      {/* Glow blobs */}
      <div className="fixed pointer-events-none" style={{ width:'600px',height:'600px',borderRadius:'50%',background:'radial-gradient(circle, rgba(0,212,255,0.06) 0%, transparent 70%)',top:'-100px',left:'-100px' }} />
      <div className="fixed pointer-events-none" style={{ width:'400px',height:'400px',borderRadius:'50%',background:'radial-gradient(circle, rgba(167,139,250,0.05) 0%, transparent 70%)',bottom:'0',right:'0' }} />

      <div className="w-full max-w-md relative z-10">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4" style={{ background:'linear-gradient(135deg, rgba(0,212,255,0.15), rgba(0,212,255,0.3))', border:'1px solid rgba(0, 212, 255, 0.4)', boxShadow:'0 0 40px rgba(0, 212, 255, 0.25)' }}>
            <Shield className="w-8 h-8" style={{ color: '#00d4ff' }} />
          </div>
          <h1 style={{ fontSize:'26px', fontWeight:800, color:'white', letterSpacing:'-0.02em' }}>Phish Guard</h1>
          <p style={{ fontSize:'13px', color:'#4a6080', marginTop:'4px' }}>
            {isAdminCreating ? 'Create New User Account' : 'Create Your Account'}
          </p>
        </div>

        {/* Card */}
        <div className="rounded-2xl p-8 relative" style={{ backgroundColor:'#0d1225', border:'1px solid #1a2040', boxShadow:'0 0 60px rgba(0,0,0,0.5)' }}>
          <div className="absolute top-0 left-0 right-0 h-0.5 rounded-t-2xl" style={{ background:'linear-gradient(90deg, transparent, #a78bfa, #00d4ff, transparent)' }} />

          <h2 style={{ fontSize:'18px', fontWeight:700, color:'white', marginBottom:'4px' }}>
            {isAdminCreating ? 'New User' : 'Sign Up'}
          </h2>
          <p style={{ fontSize:'13px', color:'#4a6080', marginBottom:'20px' }}>
            {isAdminCreating ? 'Fill in the details to create a new account' : 'Join the Phish Guard security platform'}
          </p>

          {error && (
            <div className="flex items-start gap-2 px-4 py-3 rounded-xl mb-4" style={{ backgroundColor:'rgba(239,68,68,0.08)', border:'1px solid rgba(239,68,68,0.25)' }}>
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" style={{ color:'#ef4444' }} />
              <p style={{ fontSize:'13px', color:'#ef4444' }}>{error}</p>
            </div>
          )}

          {success && (
            <div className="flex items-center gap-2 px-4 py-3 rounded-xl mb-4" style={{ backgroundColor:'rgba(34,197,94,0.08)', border:'1px solid rgba(34,197,94,0.25)' }}>
              <CheckCircle className="w-4 h-4" style={{ color:'#22c55e' }} />
              <p style={{ fontSize:'13px', color:'#22c55e' }}>{success}</p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            {/* Full Name */}
            <div>
              <label style={{ fontSize:'11px', color:'#6b7f9e', display:'block', marginBottom:'8px', textTransform:'uppercase', letterSpacing:'0.08em', fontWeight:600 }}>Full Name</label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: focused==='name' ? '#00d4ff':'#4a6080' }} />
                <input type="text" value={form.name} onChange={e => setForm({...form, name:e.target.value})}
                  onFocus={() => setFocused('name')} onBlur={() => setFocused(null)}
                  placeholder="Your full name" style={{ ...inputStyle('name'), paddingLeft:'44px' }} required />
              </div>
            </div>

            {/* Email */}
            <div>
              <label style={{ fontSize:'11px', color:'#6b7f9e', display:'block', marginBottom:'8px', textTransform:'uppercase', letterSpacing:'0.08em', fontWeight:600 }}>Email Address</label>
              <div className="relative">
                <Mail className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: focused==='email' ? '#00d4ff':'#4a6080' }} />
                <input type="email" value={form.email} onChange={e => setForm({...form, email:e.target.value})}
                  onFocus={() => setFocused('email')} onBlur={() => setFocused(null)}
                  placeholder="your@email.com" style={{ ...inputStyle('email'), paddingLeft:'44px' }} required />
              </div>
            </div>

            {/* Password */}
            <div>
              <label style={{ fontSize:'11px', color:'#6b7f9e', display:'block', marginBottom:'8px', textTransform:'uppercase', letterSpacing:'0.08em', fontWeight:600 }}>Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: focused==='pwd' ? '#00d4ff':'#4a6080' }} />
                <input type={showPwd ? 'text':'password'} value={form.password}
                  onChange={e => setForm({...form, password:e.target.value})}
                  onFocus={() => setFocused('pwd')} onBlur={() => setFocused(null)}
                  placeholder="Min 6 characters" style={{ ...inputStyle('pwd'), paddingLeft:'44px', paddingRight:'44px' }} required />
                <button type="button" onClick={() => setShowPwd(!showPwd)} className="absolute right-4 top-1/2 -translate-y-1/2" style={{ color: showPwd ? '#00d4ff':'#4a6080' }}>
                  {showPwd ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                </button>
              </div>
              {/* Strength bar */}
              {form.password && (
                <div className="mt-2">
                  <div className="flex gap-1 mb-1">
                    {[1,2,3,4].map(i => (
                      <div key={i} className="h-1 flex-1 rounded-full transition-all" style={{ backgroundColor: i <= strength ? strengthColor : '#1a2040' }} />
                    ))}
                  </div>
                  <span style={{ fontSize:'11px', color: strengthColor }}>{strengthLabel}</span>
                </div>
              )}
            </div>

            {/* Confirm Password */}
            <div>
              <label style={{ fontSize:'11px', color:'#6b7f9e', display:'block', marginBottom:'8px', textTransform:'uppercase', letterSpacing:'0.08em', fontWeight:600 }}>Confirm Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: focused==='cfm' ? '#00d4ff':'#4a6080' }} />
                <input type={showCfm ? 'text':'password'} value={form.confirmPassword}
                  onChange={e => setForm({...form, confirmPassword:e.target.value})}
                  onFocus={() => setFocused('cfm')} onBlur={() => setFocused(null)}
                  placeholder="Repeat your password" style={{ ...inputStyle('cfm'), paddingLeft:'44px', paddingRight:'44px', borderColor: form.confirmPassword && form.confirmPassword !== form.password ? 'rgba(239,68,68,0.5)' : focused==='cfm' ? 'rgba(0,212,255,0.5)' : '#1a2040' }} required />
                <button type="button" onClick={() => setShowCfm(!showCfm)} className="absolute right-4 top-1/2 -translate-y-1/2" style={{ color: showCfm ? '#00d4ff':'#4a6080' }}>
                  {showCfm ? <EyeOff className="w-4 h-4"/> : <Eye className="w-4 h-4"/>}
                </button>
              </div>
              {form.confirmPassword && form.confirmPassword !== form.password && (
                <p style={{ fontSize:'11px', color:'#ef4444', marginTop:'4px' }}>Passwords do not match</p>
              )}
            </div>

            {/* Submit */}
            <button type="submit" disabled={loading}
              className="w-full py-3 rounded-xl transition-all duration-200 mt-2"
              style={{ background: loading ? 'rgba(167,139,250,0.4)' : 'linear-gradient(135deg, #a78bfa, #00d4ff)', color:'#0a0e1a', fontWeight:700, fontSize:'14px', boxShadow: loading ? 'none' : '0 0 24px rgba(167,139,250,0.3)', cursor: loading ? 'not-allowed':'pointer' }}>
              {loading
                ? <span className="flex items-center justify-center gap-2"><span className="w-4 h-4 rounded-full border-2 border-current border-t-transparent animate-spin inline-block"/>Creating account…</span>
                : (isAdminCreating ? 'Create User Account' : 'Create Account')
              }
            </button>
          </form>
        </div>

        {/* Back to login */}
        {!isAdminCreating && (
          <p className="text-center mt-5" style={{ fontSize:'13px', color:'#4a6080' }}>
            Already have an account?{' '}
            <button onClick={onBackToLogin} className="transition-colors" style={{ color:'#00d4ff', fontWeight:600 }}>
              Sign In
            </button>
          </p>
        )}
      </div>
    </div>
  );
}
