/**
 * Landing.jsx — GuardianBox Home Page
 */
import { useNavigate } from 'react-router-dom';

const FEATURES = [
  {
    icon: '🔐',
    title: 'Zero-Knowledge Server',
    desc:  'The server stores only encrypted gibberish. Without your key, it is mathematically unreadable.',
  },
  {
    icon: '🌐',
    title: 'Browser-Native Crypto',
    desc:  'AES-256-GCM runs inside the Web Crypto API — hardware-accelerated, no third-party libraries.',
  },
  {
    icon: '🔗',
    title: 'Key in the Link',
    desc:  'The decryption key lives after the # in the URL. Browsers never send the # to the server.',
  },
  {
    icon: '💥',
    title: 'Ephemeral by Default',
    desc:  'Set time-based expiry or burn-after-reading limits. Files self-destruct automatically.',
  },
  {
    icon: '🛡️',
    title: 'Tamper Detection',
    desc:  'AES-GCM includes an authentication tag. Any tampering with the ciphertext is instantly detected.',
  },
  {
    icon: '🔑',
    title: 'PBKDF2 Key Derivation',
    desc:  'Password mode runs 100,000 PBKDF2 iterations — brute-force attacks become computationally prohibitive.',
  },
];

export default function Landing() {
  const navigate = useNavigate();

  return (
    <div className="landing">

      <div className="hero">
        <div className="hero-badge">🔒 End-to-End Encrypted</div>
        <h1 className="hero-title">
          File sharing where<br />
          <span className="hero-accent">the server is blind.</span>
        </h1>
        <p className="hero-subtitle">
          Your file is encrypted in this browser before it leaves your device.
          The server receives only encrypted bytes it can never read.
        </p>
        <div className="hero-actions">
          <button className="btn-primary btn-lg" onClick={() => navigate('/upload')}>
            🔒 Encrypt a File
          </button>
        </div>
      </div>

      {/* How it works */}
      <section className="how-it-works">
        <h2 className="section-title">How GuardianBox Works</h2>
        <div className="steps">
          {[
            { n: '01', title: 'Select a file',        desc: 'Pick any file from your device. Nothing is sent yet.' },
            { n: '02', title: 'Browser encrypts it',  desc: 'AES-256-GCM runs client-side. The key is generated locally.' },
            { n: '03', title: 'Upload the ciphertext',desc: 'Only encrypted bytes reach the server. It has zero knowledge.' },
            { n: '04', title: 'Share the link',       desc: 'The key embeds in the URL # fragment — never seen by the server.' },
            { n: '05', title: 'Recipient decrypts',   desc: 'Their browser reads the key from the URL and decrypts locally.' },
          ].map((step) => (
            <div key={step.n} className="step">
              <div className="step-number">{step.n}</div>
              <div className="step-content">
                <h3>{step.title}</h3>
                <p>{step.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Feature Grid */}
      <section className="features">
        <h2 className="section-title">Security Architecture</h2>
        <div className="feature-grid">
          {FEATURES.map((f) => (
            <div key={f.title} className="feature-card">
              <div className="feature-icon">{f.icon}</div>
              <h3 className="feature-title">{f.title}</h3>
              <p className="feature-desc">{f.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Threat Model */}
      <section className="threat-model">
        <h2 className="section-title">Threat Model — What GuardianBox Protects Against</h2>
        <div className="threat-grid">
          <div className="threat-card protected">
            <h3>✅ Protected</h3>
            <ul>
              <li>Server-side data breach</li>
              <li>S3 bucket compromise</li>
              <li>Database leak</li>
              <li>Man-in-the-middle (HTTPS)</li>
              <li>Server subpoena / legal demand</li>
              <li>Admin snooping</li>
            </ul>
          </div>
          <div className="threat-card risk">
            <h3>⚠️ Out of Scope</h3>
            <ul>
              <li>Compromised recipient device</li>
              <li>Link interception (share securely)</li>
              <li>Weak passwords (use strong ones)</li>
              <li>Browser extension malware</li>
              <li>User losing the link</li>
            </ul>
          </div>
        </div>
      </section>

    </div>
  );
}
