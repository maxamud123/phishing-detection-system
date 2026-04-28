import { useState, useMemo } from 'react';
import {
  Search, ChevronDown, ChevronUp, BookOpen, Mail, Globe, Smartphone,
  Users, CreditCard, Shield, AlertTriangle, ExternalLink, Tag,
} from 'lucide-react';

interface Article {
  id: string;
  title: string;
  category: string;
  difficulty: 'Beginner' | 'Intermediate' | 'Advanced';
  tags: string[];
  summary: string;
  body: Section[];
  examples?: string[];
  redFlags?: string[];
}

interface Section {
  heading: string;
  text: string;
}

const CATEGORIES = ['All', 'Email', 'URL', 'Social Engineering', 'Mobile', 'Financial', 'Defense'];

const categoryMeta: Record<string, { icon: any; color: string; bg: string; border: string }> = {
  Email:              { icon: Mail,         color: '#5A80A8', bg: 'rgba(90, 128, 168,0.1)',  border: 'rgba(90, 128, 168,0.3)'  },
  URL:                { icon: Globe,        color: '#7A9AB8', bg: 'rgba(122, 154, 184,0.1)',    border: 'rgba(122, 154, 184,0.3)'    },
  'Social Engineering':{ icon: Users,       color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',  border: 'rgba(251,191,36,0.3)'   },
  Mobile:             { icon: Smartphone,   color: '#fb923c', bg: 'rgba(251,146,60,0.1)',   border: 'rgba(251,146,60,0.3)'   },
  Financial:          { icon: CreditCard,   color: '#ef4444', bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.3)'    },
  Defense:            { icon: Shield,       color: '#22c55e', bg: 'rgba(34,197,94,0.1)',    border: 'rgba(34,197,94,0.3)'    },
};

const difficultyStyle: Record<Article['difficulty'], { color: string; bg: string; border: string }> = {
  Beginner:     { color: '#22c55e', bg: 'rgba(34,197,94,0.1)',    border: 'rgba(34,197,94,0.25)'    },
  Intermediate: { color: '#fbbf24', bg: 'rgba(251,191,36,0.1)',  border: 'rgba(251,191,36,0.25)'   },
  Advanced:     { color: '#ef4444', bg: 'rgba(239,68,68,0.1)',    border: 'rgba(239,68,68,0.25)'    },
};

const ARTICLES: Article[] = [
  {
    id: 'kb-001',
    title: 'What is Phishing? A Complete Overview',
    category: 'Email',
    difficulty: 'Beginner',
    tags: ['phishing', 'basics', 'email'],
    summary: 'An introduction to phishing attacks — what they are, why they work, and how to recognise them.',
    body: [
      {
        heading: 'Definition',
        text: 'Phishing is a type of social engineering attack where an attacker impersonates a trusted entity to trick victims into revealing sensitive information such as passwords, credit card numbers, or personal data. The term derives from "fishing" — attackers cast a wide net hoping someone takes the bait.',
      },
      {
        heading: 'How it works',
        text: 'Attackers send seemingly legitimate messages — usually by email — that contain a malicious link or attachment. The link typically leads to a fake login page that captures credentials, while attachments may deliver malware. The messages are crafted to create urgency, exploiting psychological pressure to make victims act without thinking.',
      },
      {
        heading: 'Why it is so effective',
        text: 'Phishing succeeds because it targets human psychology rather than technical vulnerabilities. Urgency ("your account will be closed"), authority ("this is from your bank"), and fear ("suspicious activity detected") override rational thinking. Even security-aware users can be fooled by well-crafted attacks.',
      },
    ],
    examples: [
      'An email claiming your Netflix payment failed, asking you to update billing details',
      'A message from "IT Support" telling you to reset your password via a link',
      'An alert from "PayPal" that unusual activity was detected on your account',
    ],
    redFlags: [
      'Generic greetings like "Dear Customer" instead of your name',
      'Urgent language demanding immediate action',
      'Mismatched sender domain (e.g. support@paypa1.com)',
      'Links that hover to a different URL than displayed',
    ],
  },
  {
    id: 'kb-002',
    title: 'Spear Phishing: Targeted Attacks',
    category: 'Email',
    difficulty: 'Intermediate',
    tags: ['spear phishing', 'targeted', 'OSINT'],
    summary: 'Unlike bulk phishing, spear phishing attacks are highly personalised and targeted at specific individuals or organisations.',
    body: [
      {
        heading: 'What sets it apart',
        text: 'Spear phishing attacks are researched and tailored. Attackers gather information about the target from LinkedIn, company websites, and social media (OSINT — Open Source Intelligence) to craft messages that feel genuine. They may address you by name, mention your role, your manager, or a recent project.',
      },
      {
        heading: 'Common targeting vectors',
        text: 'Executives (whaling), finance departments (business email compromise), and IT staff are prime targets. Attackers often impersonate CEOs requesting urgent wire transfers, or IT helpdesk asking employees to verify credentials.',
      },
      {
        heading: 'Attack process',
        text: 'Reconnaissance → Crafting a believable pretext → Delivering the lure → Capturing credentials or deploying malware → Lateral movement within the organisation. The reconnaissance phase can take weeks before the attack is launched.',
      },
    ],
    examples: [
      'An email from your "CEO" asking for an urgent wire transfer while they are "travelling"',
      'A message from a known vendor with an invoice attachment that installs malware',
      'A LinkedIn connection followed by a message with a "collaboration document" link',
    ],
    redFlags: [
      'Unusual requests involving money or credentials, even from known contacts',
      'Pressure to bypass normal approval processes',
      'Email sent from a lookalike domain (company-name.co instead of company-name.com)',
      'Requests for secrecy ("do not tell anyone about this")',
    ],
  },
  {
    id: 'kb-003',
    title: 'Malicious URLs: Anatomy of a Phishing Link',
    category: 'URL',
    difficulty: 'Intermediate',
    tags: ['URL', 'domain', 'homoglyph', 'typosquatting'],
    summary: 'How attackers craft deceptive URLs to bypass suspicion, and the technical indicators that reveal them.',
    body: [
      {
        heading: 'Typosquatting',
        text: 'Attackers register domains with common typos of legitimate brands — "gooogle.com", "amazoon.com", or character substitutions like "paypa1.com" (number 1 instead of letter l). Victims who mistype or don\'t look carefully are redirected to credential-harvesting pages.',
      },
      {
        heading: 'Subdomain abuse',
        text: 'Placing the legitimate brand name as a subdomain fools casual readers. For example: "paypal.com.login-verify.xyz" — the actual domain is "login-verify.xyz" but at a glance "paypal.com" appears prominent. Attackers exploit the tendency to read left-to-right.',
      },
      {
        heading: 'Homoglyph attacks',
        text: 'Unicode characters from other scripts look nearly identical to Latin letters. "аpple.com" may use a Cyrillic "а" instead of the Latin "a". These are virtually indistinguishable visually but resolve to a completely different domain.',
      },
      {
        heading: 'URL shorteners',
        text: 'Services like bit.ly obscure the final destination. Attackers use them to bypass reputation-based filters and make the link look neutral. Always expand shortened URLs before clicking — hover reveals the preview in many email clients.',
      },
    ],
    examples: [
      'http://paypa1-confirm.top/account/verify',
      'https://amazon.com.secure-login.xyz/signin',
      'https://short.url/abc123 → redirects to credential harvester',
    ],
    redFlags: [
      'Suspicious TLDs: .xyz, .top, .club, .tk, .ml, .pw',
      'IP address in place of domain name (http://192.168.1.1/login)',
      'Excessive hyphens or numbers in the domain',
      'Non-standard ports (:8080, :4443) on consumer-facing sites',
      'HTTP instead of HTTPS for pages requesting login or payment',
    ],
  },
  {
    id: 'kb-004',
    title: 'Smishing: SMS-Based Phishing',
    category: 'Mobile',
    difficulty: 'Beginner',
    tags: ['smishing', 'SMS', 'mobile', 'text message'],
    summary: 'Phishing via text messages — how attackers use SMS to steal credentials and deliver malware to mobile devices.',
    body: [
      {
        heading: 'What is smishing?',
        text: 'Smishing (SMS + phishing) uses text messages to trick recipients into clicking malicious links or calling fraudulent phone numbers. Because SMS feels personal and urgent, and mobile browsers make URLs harder to inspect, smishing has a higher click-through rate than email phishing.',
      },
      {
        heading: 'Common pretexts',
        text: 'Package delivery issues (USPS, FedEx, DHL), bank fraud alerts, two-factor authentication codes, prize notifications, and government benefit updates are the most common lures. The messages create urgency and often include a short link that hides the real destination.',
      },
      {
        heading: 'On-device risks',
        text: 'Clicking a smishing link on mobile may automatically download an APK (Android malware) or redirect to a credential harvesting page styled for mobile. Some attacks exploit browser vulnerabilities to install stalkerware silently.',
      },
    ],
    examples: [
      '"Your USPS package is held. Update your delivery address: bit.ly/track12"',
      '"[BANK] Unusual activity detected. Verify now or your card will be blocked: link"',
      '"Congratulations! You\'ve been selected for a $500 gift card. Claim: url"',
    ],
    redFlags: [
      'Unexpected messages from delivery companies you weren\'t expecting',
      'Links in messages from unknown numbers',
      'Requests to call a phone number to "verify" your account',
      'Messages that arrive at odd hours or use poor grammar',
    ],
  },
  {
    id: 'kb-005',
    title: 'Business Email Compromise (BEC)',
    category: 'Financial',
    difficulty: 'Advanced',
    tags: ['BEC', 'wire fraud', 'CEO fraud', 'invoice fraud'],
    summary: 'One of the most financially damaging cyber threats — how attackers impersonate executives and vendors to authorise fraudulent wire transfers.',
    body: [
      {
        heading: 'Overview',
        text: 'Business Email Compromise is a sophisticated scam targeting organisations that make wire transfers. The FBI estimates BEC has caused over $50 billion in global losses. Unlike malware-based attacks, BEC relies purely on social engineering — no malicious attachments or links are required.',
      },
      {
        heading: 'Attack variants',
        text: 'CEO fraud: impersonating the CEO to pressure finance staff to transfer funds. Vendor impersonation: sending fake invoices from lookalike vendor email addresses. Account takeover: gaining access to a legitimate email account to send requests from within. Payroll diversion: redirecting employee salary to attacker-controlled bank accounts.',
      },
      {
        heading: 'Why it succeeds',
        text: 'Employees are conditioned to comply with requests from authority figures, especially when the request is framed as urgent and confidential. Attackers do extensive research to know when executives travel, who handles finances, and which vendors the company uses.',
      },
      {
        heading: 'Detection and prevention',
        text: 'Implement out-of-band verification for any wire transfer request — call the requester using a known phone number (not one from the email). Require dual authorisation for large transfers. Configure email authentication (DMARC, DKIM, SPF) to prevent domain spoofing.',
      },
    ],
    examples: [
      'An email from "CEO" to CFO: "I\'m in a meeting, please wire $45,000 to our new supplier urgently"',
      'Vendor invoice with updated bank details — the email domain is company-name.co instead of .com',
      'HR receives an email from an "employee" requesting salary to be redirected to a new account',
    ],
    redFlags: [
      'Wire transfer requests that bypass normal approval channels',
      'Instructions to keep the transaction confidential',
      'Reply-to address that differs from the From address',
      'Unusual urgency or claims the CEO is unavailable for calls',
    ],
  },
  {
    id: 'kb-006',
    title: 'Vishing: Voice Phishing',
    category: 'Social Engineering',
    difficulty: 'Intermediate',
    tags: ['vishing', 'phone', 'voice', 'social engineering'],
    summary: 'Phone-based phishing where attackers call victims directly, impersonating banks, government agencies, or IT support.',
    body: [
      {
        heading: 'How vishing works',
        text: 'Attackers call targets directly, using spoofed caller IDs that display legitimate numbers (e.g. your bank\'s support line). They create urgency — "your account has been compromised", "you owe back taxes", or "your computer has a virus" — and guide victims to reveal credentials, install remote access software, or transfer funds.',
      },
      {
        heading: 'AI voice cloning',
        text: 'Emerging AI tools can clone a person\'s voice from just a few seconds of audio found on social media. Attackers use these to impersonate family members or colleagues in distress. A parent may receive a call from their "child\'s" cloned voice asking for emergency money.',
      },
      {
        heading: 'Tech support scams',
        text: 'A common variant: victims receive a call claiming their computer is sending "error signals." The caller (posing as Microsoft, Apple, or their ISP) asks them to install remote desktop software like AnyDesk, then proceeds to steal files, install malware, and demand payment to "fix" the fabricated issue.',
      },
    ],
    examples: [
      '"This is the IRS. You owe $1,400 in back taxes. Pay now or face arrest."',
      '"Your bank account has been compromised. Please confirm your card number to secure it."',
      '"This is Microsoft support. Your computer is sending error reports. Allow us remote access."',
    ],
    redFlags: [
      'Unsolicited calls creating extreme urgency or threatening arrest',
      'Requests to pay via gift cards, wire transfer, or cryptocurrency',
      'Asking for remote access to your computer',
      'Caller ID can be spoofed — do not trust it alone',
    ],
  },
  {
    id: 'kb-007',
    title: 'How to Defend Against Phishing',
    category: 'Defense',
    difficulty: 'Beginner',
    tags: ['defense', 'MFA', 'security', 'best practices'],
    summary: 'Practical steps individuals and organisations can take to reduce phishing risk and limit the impact of successful attacks.',
    body: [
      {
        heading: 'Enable Multi-Factor Authentication (MFA)',
        text: 'MFA is the single most effective protection against phished credentials. Even if an attacker obtains your password, they cannot access your account without the second factor. Use a hardware key (YubiKey) or authenticator app (not SMS, which is vulnerable to SIM swapping) wherever possible.',
      },
      {
        heading: 'Verify before you click',
        text: 'Hover over links to preview the URL before clicking. Navigate to sensitive sites by typing the address directly in your browser rather than following email links. When in doubt, contact the sender through a separate channel to verify the message is genuine.',
      },
      {
        heading: 'Use a password manager',
        text: 'Password managers autofill credentials only on the exact domain they were saved for. If you land on a phishing site that looks identical to your bank, the manager will not autofill — a silent but powerful signal that something is wrong.',
      },
      {
        heading: 'Keep software updated',
        text: 'Browser and OS updates patch vulnerabilities that phishing attacks may exploit to deliver drive-by malware when you visit a malicious page. Enable automatic updates and do not ignore security patches.',
      },
      {
        heading: 'Report suspicious messages',
        text: 'Use the "Report phishing" feature in your email client or forward to your organisation\'s security team. Reporting helps train spam filters and may protect colleagues from the same attack.',
      },
    ],
    redFlags: [
      'Any unsolicited request for credentials, payment, or personal data',
      'Pressure to act immediately without time to think',
      'Requests that deviate from normal process (call your IT desk to verify)',
    ],
  },
  {
    id: 'kb-008',
    title: 'Pharming: DNS Hijacking Attacks',
    category: 'URL',
    difficulty: 'Advanced',
    tags: ['pharming', 'DNS', 'hijacking', 'MITM'],
    summary: 'A stealthier cousin of phishing — pharming redirects users to fake websites without any malicious link being clicked.',
    body: [
      {
        heading: 'What is pharming?',
        text: 'Pharming attacks corrupt the DNS resolution process so that a legitimate URL typed by the user resolves to an attacker-controlled IP address. Unlike phishing, the victim does not need to click a suspicious link — they type the correct address in their browser and are silently redirected.',
      },
      {
        heading: 'Attack methods',
        text: 'Local hosts file poisoning: malware modifies the hosts file on a victim\'s computer to redirect specific domains. DNS server compromise: attackers breach a DNS provider and alter records at the source, affecting every user who queries that server. Router compromise: attacking the home or office router\'s DNS settings affects all devices on the network.',
      },
      {
        heading: 'Detection',
        text: 'Check for the padlock and certificate details when on sensitive sites. A pharming page may not have a valid TLS certificate, or the certificate may be issued to an unexpected organisation. Use DNSSEC-aware resolvers (e.g. Cloudflare 1.1.1.1 or Google 8.8.8.8) which validate DNS responses.',
      },
    ],
    examples: [
      'User types "bank.com" → DNS returns attacker\'s IP → fake bank site loads at the correct URL',
      'Router DNS changed to rogue server → all devices silently redirected on sensitive domains',
    ],
    redFlags: [
      'Browser certificate warning on a site you visit regularly',
      'Site looks slightly different — logo, layout, or font changes',
      'Password manager does not autofill (domain mismatch detected)',
      'Unexpected login prompts on sites where you are already logged in',
    ],
  },
];

export function KnowledgeBase() {
  const [search, setSearch]     = useState('');
  const [category, setCategory] = useState('All');
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = useMemo(() =>
    ARTICLES.filter(a => {
      const q = search.toLowerCase();
      const matchSearch = !q ||
        a.title.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.tags.some(t => t.toLowerCase().includes(q));
      const matchCat = category === 'All' || a.category === category;
      return matchSearch && matchCat;
    }),
    [search, category]
  );

  const stats = {
    total:    ARTICLES.length,
    beginner: ARTICLES.filter(a => a.difficulty === 'Beginner').length,
    inter:    ARTICLES.filter(a => a.difficulty === 'Intermediate').length,
    advanced: ARTICLES.filter(a => a.difficulty === 'Advanced').length,
  };

  return (
    <div className="space-y-6 max-w-4xl mx-auto">
      {/* Header */}
      <div>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'white' }}>Knowledge Base</h2>
        <p style={{ fontSize: '13px', color: '#5A80A8', marginTop: '4px' }}>
          Learn about phishing techniques, attack vectors, and how to defend against them
        </p>
      </div>

      {/* Stat Row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Total Articles', value: stats.total,    color: '#7A9AB8', bg: 'rgba(122, 154, 184,0.08)',   border: 'rgba(122, 154, 184,0.2)'   },
          { label: 'Beginner',       value: stats.beginner, color: '#22c55e', bg: 'rgba(34,197,94,0.08)',  border: 'rgba(34,197,94,0.2)'   },
          { label: 'Intermediate',   value: stats.inter,    color: '#fbbf24', bg: 'rgba(251,191,36,0.08)', border: 'rgba(251,191,36,0.2)'  },
          { label: 'Advanced',       value: stats.advanced, color: '#ef4444', bg: 'rgba(239,68,68,0.08)',  border: 'rgba(239,68,68,0.2)'   },
        ].map(s => (
          <div key={s.label} className="p-3 rounded-xl flex items-center gap-3"
            style={{ backgroundColor: s.bg, border: `1px solid ${s.border}` }}>
            <div>
              <div style={{ fontSize: '22px', fontWeight: 800, color: s.color, lineHeight: 1 }}>{s.value}</div>
              <div style={{ fontSize: '11px', color: '#5A80A8', marginTop: '2px' }}>{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Search + Category Filter */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="flex-1 relative">
          <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2" style={{ color: '#3A5A7A' }} />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search articles, topics, or tags..."
            style={{
              backgroundColor: '#2A0010',
              border: '1px solid #4A001A',
              borderRadius: '10px',
              color: 'white',
              fontSize: '13px',
              outline: 'none',
              padding: '9px 14px 9px 36px',
              width: '100%',
            }}
          />
        </div>
      </div>

      {/* Category Tabs */}
      <div className="flex flex-wrap gap-2">
        {CATEGORIES.map(cat => {
          const meta = cat !== 'All' ? categoryMeta[cat] : null;
          const active = category === cat;
          return (
            <button
              key={cat}
              onClick={() => setCategory(cat)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs transition-all duration-200"
              style={active
                ? {
                    backgroundColor: meta ? meta.bg : 'rgba(122, 154, 184,0.12)',
                    border: `1px solid ${meta ? meta.border : 'rgba(122, 154, 184,0.35)'}`,
                    color: meta ? meta.color : '#7A9AB8',
                    fontWeight: 700,
                  }
                : {
                    backgroundColor: 'rgba(255,255,255,0.03)',
                    border: '1px solid #4A001A',
                    color: '#3A5A7A',
                  }
              }
            >
              {meta && <meta.icon className="w-3 h-3" />}
              {cat === 'All' && <BookOpen className="w-3 h-3" />}
              {cat}
            </button>
          );
        })}
      </div>

      {/* Result count */}
      <p style={{ fontSize: '12px', color: '#3A5A7A' }}>
        {filtered.length} article{filtered.length !== 1 ? 's' : ''}
        {category !== 'All' ? ` in ${category}` : ''}
        {search ? ` matching "${search}"` : ''}
      </p>

      {/* Articles */}
      <div className="space-y-3">
        {filtered.length === 0 && (
          <div className="py-16 text-center" style={{ color: '#3A5A7A' }}>
            <BookOpen className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p>No articles match your search.</p>
          </div>
        )}
        {filtered.map(article => {
          const isOpen = expanded === article.id;
          const meta   = categoryMeta[article.category];
          const diff   = difficultyStyle[article.difficulty];
          const Icon   = meta.icon;

          return (
            <div
              key={article.id}
              className="rounded-2xl overflow-hidden transition-all duration-200"
              style={{
                backgroundColor: '#2A0010',
                border: `1px solid ${isOpen ? meta.border : '#4A001A'}`,
                boxShadow: isOpen ? `0 0 24px ${meta.bg}` : 'none',
              }}
            >
              {/* Header row — always visible */}
              <button
                className="w-full text-left px-5 py-4 flex items-start gap-4 transition-colors hover:bg-white/[0.02]"
                onClick={() => setExpanded(isOpen ? null : article.id)}
              >
                {/* Category icon */}
                <div
                  className="p-2 rounded-xl shrink-0 mt-0.5"
                  style={{ backgroundColor: meta.bg, border: `1px solid ${meta.border}` }}
                >
                  <Icon className="w-4 h-4" style={{ color: meta.color }} />
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex flex-wrap items-center gap-2 mb-1">
                    <span style={{ fontSize: '15px', fontWeight: 600, color: 'white' }}>{article.title}</span>
                  </div>
                  <p style={{ fontSize: '13px', color: '#5A80A8', lineHeight: 1.5 }}>{article.summary}</p>
                  <div className="flex flex-wrap items-center gap-2 mt-2">
                    <span
                      className="px-2 py-0.5 rounded-md text-xs font-semibold"
                      style={{ color: meta.color, backgroundColor: meta.bg, border: `1px solid ${meta.border}` }}
                    >
                      {article.category}
                    </span>
                    <span
                      className="px-2 py-0.5 rounded-md text-xs font-semibold"
                      style={{ color: diff.color, backgroundColor: diff.bg, border: `1px solid ${diff.border}` }}
                    >
                      {article.difficulty}
                    </span>
                    {article.tags.slice(0, 3).map(tag => (
                      <span key={tag} className="flex items-center gap-1 px-2 py-0.5 rounded-md text-xs"
                        style={{ color: '#3A5A7A', backgroundColor: 'rgba(255,255,255,0.03)', border: '1px solid #4A001A' }}>
                        <Tag className="w-2.5 h-2.5" />{tag}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="shrink-0 mt-1" style={{ color: '#3A5A7A' }}>
                  {isOpen ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
                </div>
              </button>

              {/* Expanded body */}
              {isOpen && (
                <div style={{ borderTop: `1px solid ${meta.border}` }}>
                  <div className="px-5 py-5 space-y-5">
                    {/* Sections */}
                    {article.body.map(section => (
                      <div key={section.heading}>
                        <h4 style={{ fontSize: '13px', fontWeight: 700, color: meta.color, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                          {section.heading}
                        </h4>
                        <p style={{ fontSize: '14px', color: '#94a3b8', lineHeight: 1.75 }}>{section.text}</p>
                      </div>
                    ))}

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2">
                      {/* Examples */}
                      {article.examples && (
                        <div className="p-4 rounded-xl space-y-2" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                          <div className="flex items-center gap-2 mb-3">
                            <ExternalLink className="w-4 h-4" style={{ color: '#fbbf24' }} />
                            <span style={{ fontSize: '12px', fontWeight: 700, color: '#fbbf24', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                              Real-World Examples
                            </span>
                          </div>
                          {article.examples.map((ex, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <span style={{ color: '#fbbf24', fontSize: '11px', marginTop: '3px', flexShrink: 0 }}>▸</span>
                              <p style={{ fontSize: '12px', color: '#94a3b8', lineHeight: 1.6 }}>{ex}</p>
                            </div>
                          ))}
                        </div>
                      )}

                      {/* Red Flags */}
                      {article.redFlags && (
                        <div className="p-4 rounded-xl space-y-2" style={{ backgroundColor: '#1E000A', border: '1px solid #4A001A' }}>
                          <div className="flex items-center gap-2 mb-3">
                            <AlertTriangle className="w-4 h-4" style={{ color: '#ef4444' }} />
                            <span style={{ fontSize: '12px', fontWeight: 700, color: '#ef4444', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                              Red Flags
                            </span>
                          </div>
                          {article.redFlags.map((flag, i) => (
                            <div key={i} className="flex items-start gap-2">
                              <span style={{ color: '#ef4444', fontSize: '11px', marginTop: '3px', flexShrink: 0 }}>▸</span>
                              <p style={{ fontSize: '12px', color: '#94a3b8', lineHeight: 1.6 }}>{flag}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
