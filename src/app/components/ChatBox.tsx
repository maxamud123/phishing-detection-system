import { useState, useRef, useEffect } from 'react';
import { MessageCircle, X, Send, Bot, User, Loader2, Shield, Trash2 } from 'lucide-react';
import { ChatAPI } from '../lib/api';

interface Message {
  role: 'user' | 'assistant';
  content: string;
}

const WELCOME: Message = {
  role: 'assistant',
  content: "Hi! I'm PhishGuard AI. Ask me anything about phishing threats, scan results, or cybersecurity best practices.",
};

export function ChatBox() {
  const [open, setOpen]       = useState(false);
  const [messages, setMessages] = useState<Message[]>([WELCOME]);
  const [input, setInput]     = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  useEffect(() => {
    if (open) setTimeout(() => inputRef.current?.focus(), 120);
  }, [open]);

  async function send() {
    const text = input.trim();
    if (!text || loading) return;
    setError('');
    const next: Message[] = [...messages, { role: 'user', content: text }];
    setMessages(next);
    setInput('');
    setLoading(true);
    try {
      const res = await ChatAPI.send(next.filter(m => m !== WELCOME || messages[0] !== WELCOME));
      if (res.success && res.reply) {
        setMessages(m => [...m, { role: 'assistant', content: res.reply }]);
      } else {
        setError(res.error || 'No response received.');
      }
    } catch {
      setError('Failed to reach AI service.');
    } finally {
      setLoading(false);
    }
  }

  function handleKey(e: React.KeyboardEvent) {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
  }

  function clear() {
    setMessages([WELCOME]);
    setError('');
  }

  return (
    <>
      {/* Floating button */}
      <button
        onClick={() => setOpen(o => !o)}
        className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full flex items-center justify-center shadow-2xl transition-all hover:scale-110 active:scale-95"
        style={{
          background: 'linear-gradient(135deg, #5A80A8, #5C0020)',
          boxShadow: '0 4px 24px rgba(90,128,168,0.5), 0 0 0 3px rgba(90,128,168,0.15)',
        }}
        title="PhishGuard AI Chat"
      >
        {open
          ? <X className="w-6 h-6 text-white" />
          : <MessageCircle className="w-6 h-6 text-white" />}
      </button>

      {/* Chat panel */}
      {open && (
        <div
          className="fixed bottom-24 right-6 z-50 flex flex-col rounded-2xl overflow-hidden shadow-2xl"
          style={{
            width: '360px',
            height: '520px',
            background: '#1E000A',
            border: '1px solid #4A001A',
            boxShadow: '0 8px 40px rgba(0,0,0,0.6), 0 0 0 1px rgba(90,128,168,0.15)',
          }}
        >
          {/* Header */}
          <div
            className="flex items-center gap-3 px-4 py-3 shrink-0"
            style={{ background: 'linear-gradient(135deg, #2A0010, #1A2840)', borderBottom: '1px solid #4A001A' }}
          >
            <div
              className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
              style={{ background: 'linear-gradient(135deg, rgba(90,128,168,0.3), rgba(92,0,32,0.3))', border: '1px solid rgba(90,128,168,0.4)' }}
            >
              <Shield className="w-4 h-4" style={{ color: '#5A80A8' }} />
            </div>
            <div className="flex-1 min-w-0">
              <div style={{ fontSize: '13px', fontWeight: 700, color: '#C8DCF0' }}>PhishGuard AI</div>
              <div className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: '#22c55e', boxShadow: '0 0 4px #22c55e' }} />
                <span style={{ fontSize: '10px', color: '#7A9AB8' }}>Online · Cybersecurity Assistant</span>
              </div>
            </div>
            <button
              onClick={clear}
              title="Clear chat"
              className="p-1.5 rounded-lg transition-colors hover:bg-white/10"
              style={{ color: '#7A9AB8' }}
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-3 py-3 space-y-3" style={{ scrollbarWidth: 'thin' }}>
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-2 ${m.role === 'user' ? 'flex-row-reverse' : 'flex-row'}`}>
                {/* Avatar */}
                <div
                  className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                  style={
                    m.role === 'assistant'
                      ? { background: 'rgba(90,128,168,0.2)', border: '1px solid rgba(90,128,168,0.3)' }
                      : { background: 'rgba(92,0,32,0.4)', border: '1px solid rgba(92,0,32,0.5)' }
                  }
                >
                  {m.role === 'assistant'
                    ? <Bot className="w-3.5 h-3.5" style={{ color: '#5A80A8' }} />
                    : <User className="w-3.5 h-3.5" style={{ color: '#C8DCF0' }} />}
                </div>

                {/* Bubble */}
                <div
                  className="max-w-[78%] px-3 py-2 rounded-2xl"
                  style={
                    m.role === 'assistant'
                      ? { background: '#2A0010', border: '1px solid #4A001A', color: '#C8DCF0', borderRadius: '4px 16px 16px 16px' }
                      : { background: 'linear-gradient(135deg, #5A80A8, #3A5A7A)', color: '#ffffff', borderRadius: '16px 4px 16px 16px' }
                  }
                >
                  <p style={{ fontSize: '12.5px', lineHeight: 1.6, whiteSpace: 'pre-wrap' }}>{m.content}</p>
                </div>
              </div>
            ))}

            {/* Typing indicator */}
            {loading && (
              <div className="flex gap-2">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background: 'rgba(90,128,168,0.2)', border: '1px solid rgba(90,128,168,0.3)' }}>
                  <Bot className="w-3.5 h-3.5" style={{ color: '#5A80A8' }} />
                </div>
                <div className="px-3 py-2.5 rounded-2xl flex items-center gap-1.5"
                  style={{ background: '#2A0010', border: '1px solid #4A001A', borderRadius: '4px 16px 16px 16px' }}>
                  {[0, 1, 2].map(i => (
                    <span key={i} className="w-1.5 h-1.5 rounded-full animate-bounce"
                      style={{ backgroundColor: '#5A80A8', animationDelay: `${i * 150}ms` }} />
                  ))}
                </div>
              </div>
            )}

            {/* Error */}
            {error && (
              <div className="px-3 py-2 rounded-xl text-center"
                style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', color: '#ef4444', fontSize: '11px' }}>
                {error}
              </div>
            )}

            <div ref={bottomRef} />
          </div>

          {/* Input */}
          <div className="px-3 pb-3 pt-2 shrink-0" style={{ borderTop: '1px solid #4A001A' }}>
            <div
              className="flex items-end gap-2 rounded-xl px-3 py-2"
              style={{ background: '#2A0010', border: '1px solid #4A001A' }}
            >
              <textarea
                ref={inputRef}
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={handleKey}
                placeholder="Ask about phishing, scans, threats…"
                rows={1}
                className="flex-1 bg-transparent resize-none outline-none"
                style={{
                  fontSize: '12.5px', color: '#C8DCF0', lineHeight: 1.5,
                  maxHeight: '80px', caretColor: '#5A80A8',
                }}
              />
              <button
                onClick={send}
                disabled={!input.trim() || loading}
                className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0 transition-all disabled:opacity-40"
                style={{ background: input.trim() && !loading ? 'linear-gradient(135deg, #5A80A8, #5C0020)' : '#4A001A' }}
              >
                {loading
                  ? <Loader2 className="w-3.5 h-3.5 text-white animate-spin" />
                  : <Send className="w-3.5 h-3.5 text-white" />}
              </button>
            </div>
            <p style={{ fontSize: '10px', color: '#4A6080', textAlign: 'center', marginTop: '6px' }}>
              Press Enter to send · Shift+Enter for new line
            </p>
          </div>
        </div>
      )}
    </>
  );
}
