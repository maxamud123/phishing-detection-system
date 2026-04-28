import { useState } from 'react';
import { User, Mail, Lock, CheckCircle, AlertCircle, Eye, EyeOff, Shield } from 'lucide-react';
import { AuthAPI, setUser, getUser } from '../lib/api';

export function Profile() {
  const currentUser = getUser();

  // Profile fields
  const [name,  setName]  = useState(currentUser?.name  || '');
  const [email, setEmail] = useState(currentUser?.email || '');
  const [profileMsg,  setProfileMsg]  = useState('');
  const [profileErr,  setProfileErr]  = useState('');
  const [profileSaving, setProfileSaving] = useState(false);

  // Password fields
  const [currentPwd, setCurrentPwd] = useState('');
  const [newPwd,     setNewPwd]     = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [showCur,    setShowCur]    = useState(false);
  const [showNew,    setShowNew]    = useState(false);
  const [pwdMsg,     setPwdMsg]     = useState('');
  const [pwdErr,     setPwdErr]     = useState('');
  const [pwdSaving,  setPwdSaving]  = useState(false);

  const pwdStrength = (() => {
    if (!newPwd) return 0;
    let s = 0;
    if (newPwd.length >= 8)          s++;
    if (/[A-Z]/.test(newPwd))        s++;
    if (/[0-9]/.test(newPwd))        s++;
    if (/[^A-Za-z0-9]/.test(newPwd)) s++;
    return s;
  })();
  const strengthLabel = ['', 'Weak', 'Fair', 'Good', 'Strong'][pwdStrength];
  const strengthColor = ['', '#ef4444', '#f59e0b', '#22c55e', '#7A9AB8'][pwdStrength];

  const handleProfileSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setProfileMsg(''); setProfileErr('');
    setProfileSaving(true);
    try {
      const res = await AuthAPI.updateProfile({ name: name.trim(), email: email.trim() });
      if (!res.success) { setProfileErr(res.error || 'Failed to update profile.'); return; }
      setUser(res.user);
      setProfileMsg('Profile updated successfully.');
    } catch {
      setProfileErr('Server unavailable.');
    } finally {
      setProfileSaving(false);
    }
  };

  const handlePasswordSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwdMsg(''); setPwdErr('');
    if (newPwd !== confirmPwd) { setPwdErr('Passwords do not match.'); return; }
    if (newPwd.length < 6)    { setPwdErr('Password must be at least 6 characters.'); return; }
    setPwdSaving(true);
    try {
      const res = await AuthAPI.changePassword(currentPwd, newPwd);
      if (!res.success) { setPwdErr(res.error || 'Failed to change password.'); return; }
      setPwdMsg('Password changed. You will be logged out shortly.');
      setCurrentPwd(''); setNewPwd(''); setConfirmPwd('');
      setTimeout(() => { AuthAPI.logout(); window.location.reload(); }, 2000);
    } catch {
      setPwdErr('Server unavailable.');
    } finally {
      setPwdSaving(false);
    }
  };

  const inputStyle: React.CSSProperties = {
    backgroundColor: '#1E000A',
    border: '1px solid #4A001A',
    borderRadius: '10px',
    color: 'white',
    fontSize: '14px',
    outline: 'none',
    padding: '10px 14px',
    width: '100%',
    transition: 'border-color 0.2s',
  };

  const card: React.CSSProperties = {
    backgroundColor: '#2A0010',
    border: '1px solid #4A001A',
    borderRadius: '16px',
    padding: '24px',
  };

  return (
    <div style={{ maxWidth: '680px', margin: '0 auto', padding: '8px 0' }}>
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-12 h-12 rounded-2xl flex items-center justify-center"
          style={{ background: 'linear-gradient(135deg, rgba(122, 154, 184,0.15), rgba(122, 154, 184,0.3))', border: '1px solid rgba(122, 154, 184,0.3)' }}>
          <User className="w-6 h-6" style={{ color: '#7A9AB8' }} />
        </div>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: 'white' }}>My Profile</h2>
          <p style={{ fontSize: '13px', color: '#3A5A7A' }}>Manage your account details and password</p>
        </div>
      </div>

      {/* Role badge */}
      <div style={{ ...card, marginBottom: '16px' }}>
        <div className="flex items-center gap-3">
          <Shield className="w-5 h-5" style={{ color: currentUser?.role === 'Admin' ? '#5A80A8' : '#7A9AB8' }} />
          <div>
            <p style={{ fontSize: '12px', color: '#3A5A7A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Role</p>
            <p style={{ fontSize: '14px', fontWeight: 600, color: currentUser?.role === 'Admin' ? '#5A80A8' : '#7A9AB8' }}>
              {currentUser?.role}
            </p>
          </div>
          {currentUser?.lastLogin && (
            <div style={{ marginLeft: 'auto', textAlign: 'right' }}>
              <p style={{ fontSize: '12px', color: '#3A5A7A', textTransform: 'uppercase', letterSpacing: '0.06em' }}>Last Login</p>
              <p style={{ fontSize: '13px', color: '#94a3b8' }}>
                {new Date(currentUser.lastLogin).toLocaleString()}
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Profile info */}
      <div style={{ ...card, marginBottom: '16px' }}>
        <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white', marginBottom: '16px' }}>Account Information</h3>
        <form onSubmit={handleProfileSave} className="space-y-4">
          <div>
            <label style={{ fontSize: '11px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Full Name</label>
            <div className="relative">
              <User className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: '#3A5A7A' }} />
              <input
                type="text" value={name} onChange={e => setName(e.target.value)}
                style={{ ...inputStyle, paddingLeft: '36px' }} required
              />
            </div>
          </div>
          <div>
            <label style={{ fontSize: '11px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Email Address</label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: '#3A5A7A' }} />
              <input
                type="email" value={email} onChange={e => setEmail(e.target.value)}
                style={{ ...inputStyle, paddingLeft: '36px' }} required
              />
            </div>
          </div>

          {profileErr && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <AlertCircle className="w-4 h-4 shrink-0" style={{ color: '#ef4444' }} />
              <p style={{ fontSize: '13px', color: '#ef4444' }}>{profileErr}</p>
            </div>
          )}
          {profileMsg && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ backgroundColor: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
              <CheckCircle className="w-4 h-4 shrink-0" style={{ color: '#22c55e' }} />
              <p style={{ fontSize: '13px', color: '#22c55e' }}>{profileMsg}</p>
            </div>
          )}

          <button type="submit" disabled={profileSaving}
            className="px-5 py-2 rounded-xl transition-all"
            style={{ background: 'linear-gradient(135deg, #7A9AB8, #0099bb)', color: '#3A0015', fontWeight: 700, fontSize: '13px', opacity: profileSaving ? 0.6 : 1 }}>
            {profileSaving ? 'Saving…' : 'Save Changes'}
          </button>
        </form>
      </div>

      {/* Change password */}
      <div style={card}>
        <h3 style={{ fontSize: '15px', fontWeight: 600, color: 'white', marginBottom: '16px' }}>Change Password</h3>
        <form onSubmit={handlePasswordSave} className="space-y-4">
          <div>
            <label style={{ fontSize: '11px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Current Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: '#3A5A7A' }} />
              <input
                type={showCur ? 'text' : 'password'} value={currentPwd}
                onChange={e => setCurrentPwd(e.target.value)}
                style={{ ...inputStyle, paddingLeft: '36px', paddingRight: '36px' }} required
              />
              <button type="button" onClick={() => setShowCur(!showCur)}
                className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: '#3A5A7A' }}>
                {showCur ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <div>
            <label style={{ fontSize: '11px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>New Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: '#3A5A7A' }} />
              <input
                type={showNew ? 'text' : 'password'} value={newPwd}
                onChange={e => setNewPwd(e.target.value)}
                style={{ ...inputStyle, paddingLeft: '36px', paddingRight: '36px' }} required
              />
              <button type="button" onClick={() => setShowNew(!showNew)}
                className="absolute right-3 top-1/2 -translate-y-1/2" style={{ color: '#3A5A7A' }}>
                {showNew ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
            {newPwd && (
              <div className="mt-2">
                <div className="flex gap-1 mb-1">
                  {[1,2,3,4].map(i => (
                    <div key={i} className="h-1 flex-1 rounded-full transition-all"
                      style={{ backgroundColor: i <= pwdStrength ? strengthColor : '#4A001A' }} />
                  ))}
                </div>
                <span style={{ fontSize: '11px', color: strengthColor }}>{strengthLabel}</span>
              </div>
            )}
          </div>

          <div>
            <label style={{ fontSize: '11px', color: '#5A80A8', display: 'block', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.07em', fontWeight: 600 }}>Confirm New Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: '#3A5A7A' }} />
              <input
                type="password" value={confirmPwd}
                onChange={e => setConfirmPwd(e.target.value)}
                style={{ ...inputStyle, paddingLeft: '36px', borderColor: confirmPwd && confirmPwd !== newPwd ? 'rgba(239,68,68,0.5)' : '#4A001A' }}
                required
              />
            </div>
            {confirmPwd && confirmPwd !== newPwd && (
              <p style={{ fontSize: '11px', color: '#ef4444', marginTop: '4px' }}>Passwords do not match</p>
            )}
          </div>

          {pwdErr && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ backgroundColor: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
              <AlertCircle className="w-4 h-4 shrink-0" style={{ color: '#ef4444' }} />
              <p style={{ fontSize: '13px', color: '#ef4444' }}>{pwdErr}</p>
            </div>
          )}
          {pwdMsg && (
            <div className="flex items-center gap-2 px-3 py-2 rounded-lg" style={{ backgroundColor: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)' }}>
              <CheckCircle className="w-4 h-4 shrink-0" style={{ color: '#22c55e' }} />
              <p style={{ fontSize: '13px', color: '#22c55e' }}>{pwdMsg}</p>
            </div>
          )}

          <button type="submit" disabled={pwdSaving}
            className="px-5 py-2 rounded-xl transition-all"
            style={{ background: 'linear-gradient(135deg, #5A80A8, #5C0020)', color: 'white', fontWeight: 700, fontSize: '13px', opacity: pwdSaving ? 0.6 : 1 }}>
            {pwdSaving ? 'Changing…' : 'Change Password'}
          </button>
        </form>
      </div>
    </div>
  );
}
