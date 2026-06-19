/**
 * UploadPage.jsx — GuardianBox Upload UI
 * ───────────────────────────────────────
 * Handles the full upload workflow:
 * 1. User drops/selects a file
 * 2. User chooses auto-key or password mode
 * 3. User sets expiry options
 * 4. Encrypts file in browser (BEFORE sending anything)
 * 5. Uploads encrypted blob to backend
 * 6. Shows shareable link (with key embedded in # fragment)
 */

import { useState, useRef, useCallback } from 'react';
import {
  encryptFile,
  buildShareURL,
} from '../utils/cryptoUtils.js';

const API_BASE = import.meta.env.VITE_API_URL ||
  'http://18.61.174.171:4000/api';;

// ─── Expiry Options ───────────────────────────────────────────────────────────

const EXPIRY_OPTIONS = [
  { label: 'Never',    value: 0 },
  { label: '1 hour',   value: 3600 },
  { label: '24 hours', value: 86400 },
  { label: '7 days',   value: 604800 },
  { label: '30 days',  value: 2592000 },
];

const DOWNLOAD_OPTIONS = [
  { label: 'Unlimited',    value: 0 },
  { label: '1 download',   value: 1 },
  { label: '3 downloads',  value: 3 },
  { label: '10 downloads', value: 10 },
];

// ─── Utility ──────────────────────────────────────────────────────────────────

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k    = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i    = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`;
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function UploadPage() {
  const [file,           setFile]           = useState(null);
  const [mode,           setMode]           = useState('auto');   // 'auto' | 'password'
  const [password,       setPassword]       = useState('');
  const [confirmPwd,     setConfirmPwd]     = useState('');
  const [expiresIn,      setExpiresIn]      = useState(86400);    // 24h default
  const [maxDownloads,   setMaxDownloads]   = useState(0);
  const [isDragging,     setIsDragging]     = useState(false);
  const [status,         setStatus]         = useState('idle');   // idle|encrypting|uploading|done|error
  const [progress,       setProgress]       = useState(0);
  const [shareURL,       setShareURL]       = useState('');
  const [copied,         setCopied]         = useState(false);
  const [errorMsg,       setErrorMsg]       = useState('');

  const fileInputRef = useRef(null);

  // ─── File Selection ──────────────────────────────────────────────────────

  const handleFile = useCallback((f) => {
    if (!f) return;
    if (f.size > 100 * 1024 * 1024) {
      setErrorMsg('File exceeds the 100MB limit.');
      return;
    }
    setFile(f);
    setErrorMsg('');
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragging(false);
    const dropped = e.dataTransfer.files[0];
    handleFile(dropped);
  }, [handleFile]);

  const handleDragOver = (e) => { e.preventDefault(); setIsDragging(true);  };
  const handleDragLeave     = ()  => setIsDragging(false);

  // ─── Encrypt & Upload ────────────────────────────────────────────────────

  const handleUpload = async () => {
    if (!file) return;

    // Password mode validation
    if (mode === 'password') {
      if (password.length < 8) {
        setErrorMsg('Password must be at least 8 characters.');
        return;
      }
      if (password !== confirmPwd) {
        setErrorMsg('Passwords do not match.');
        return;
      }
    }

    setErrorMsg('');
    setStatus('encrypting');
    setProgress(10);

    try {
      // ── Step 1: Encrypt in the browser ──────────────────────────────────
      const encResult = await encryptFile(file, {
        mode,
        password: mode === 'password' ? password : undefined,
      });
      setProgress(50);

      // ── Step 2: Upload the encrypted blob ────────────────────────────────
      setStatus('uploading');

      const formData = new FormData();
      formData.append('file',         encResult.encryptedBlob, 'encrypted.bin');
      formData.append('iv',           encResult.iv);
      formData.append('salt',         encResult.salt);
      formData.append('originalName', encResult.filename);
      formData.append('mimetype',     encResult.mimetype);
      formData.append('expiresIn',    expiresIn.toString());
      formData.append('maxDownloads', maxDownloads.toString());

      const response = await fetch(`${API_BASE}/files/upload`, {
        method: 'POST',
        body:   formData,
      });

      if (!response.ok) {
        const err = await response.json().catch(() => ({ error: 'Upload failed.' }));
        throw new Error(err.error || 'Upload failed.');
      }

      const { fileId } = await response.json();
      setProgress(100);

      // ── Step 3: Build the share URL ───────────────────────────────────────
      // In auto mode: key is in the fragment
      // In password mode: user must share the password separately
      const secret  = mode === 'auto' ? encResult.keyB64 : '(use-your-password)';
      const url     = buildShareURL(fileId, { mode, secret });
      setShareURL(url);
      setStatus('done');

    } catch (err) {
      console.error('[UPLOAD ERROR]', err);
      setStatus('error');
      setErrorMsg(err.message || 'Something went wrong.');
    }
  };

  // ─── Copy to Clipboard ────────────────────────────────────────────────────

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(shareURL);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      // Fallback for older browsers
      const el    = document.createElement('textarea');
      el.value    = shareURL;
      el.style.position = 'fixed';
      el.style.opacity  = '0';
      document.body.appendChild(el);
      el.focus();
      el.select();
      document.execCommand('copy');
      document.body.removeChild(el);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    }
  };

  // ─── Reset ────────────────────────────────────────────────────────────────

  const handleReset = () => {
    setFile(null);
    setStatus('idle');
    setProgress(0);
    setShareURL('');
    setPassword('');
    setConfirmPwd('');
    setErrorMsg('');
    setCopied(false);
  };

  // ─── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="upload-page">

      {/* ── Drop Zone ── */}
      {status === 'idle' && (
        <>
          <div
            className={`drop-zone ${isDragging ? 'dragging' : ''} ${file ? 'has-file' : ''}`}
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onClick={() => !file && fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              style={{ display: 'none' }}
              onChange={(e) => handleFile(e.target.files[0])}
            />
            {file ? (
              <div className="file-info">
                <div className="file-icon">🔒</div>
                <p className="file-name">{file.name}</p>
                <p className="file-size">{formatBytes(file.size)}</p>
                <button className="btn-ghost" onClick={(e) => { e.stopPropagation(); setFile(null); }}>
                  ✕ Remove
                </button>
              </div>
            ) : (
              <div className="drop-prompt">
                <div className="drop-icon">📁</div>
                <p>Drop a file here, or <span className="link-text">click to browse</span></p>
                <p className="sub-text">Max 100MB · Any file type</p>
              </div>
            )}
          </div>

          {/* ── Options ── */}
          {file && (
            <div className="options-panel">

              {/* Mode Toggle */}
              <div className="option-group">
                <label className="option-label">Encryption Mode</label>
                <div className="mode-toggle">
                  <button
                    className={`mode-btn ${mode === 'auto' ? 'active' : ''}`}
                    onClick={() => setMode('auto')}
                  >
                    🔑 Auto Key
                    <span className="mode-hint">Key embedded in link</span>
                  </button>
                  <button
                    className={`mode-btn ${mode === 'password' ? 'active' : ''}`}
                    onClick={() => setMode('password')}
                  >
                    🔐 Password
                    <span className="mode-hint">You set the password</span>
                  </button>
                </div>
              </div>

              {/* Password Inputs */}
              {mode === 'password' && (
                <div className="option-group">
                  <label className="option-label">Password (min 8 characters)</label>
                  <input
                    className="text-input"
                    type="password"
                    placeholder="Enter a strong password..."
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete="new-password"
                  />
                  <input
                    className="text-input"
                    type="password"
                    placeholder="Confirm password..."
                    value={confirmPwd}
                    onChange={(e) => setConfirmPwd(e.target.value)}
                    autoComplete="new-password"
                  />
                </div>
              )}

              {/* Expiry */}
              <div className="option-group">
                <label className="option-label">Link Expires</label>
                <div className="chip-group">
                  {EXPIRY_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      className={`chip ${expiresIn === opt.value ? 'selected' : ''}`}
                      onClick={() => setExpiresIn(opt.value)}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Download Limit */}
              <div className="option-group">
                <label className="option-label">Download Limit</label>
                <div className="chip-group">
                  {DOWNLOAD_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      className={`chip ${maxDownloads === opt.value ? 'selected' : ''}`}
                      onClick={() => setMaxDownloads(opt.value)}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {errorMsg && <p className="error-msg">⚠ {errorMsg}</p>}

              <button className="btn-primary" onClick={handleUpload}>
                🔒 Encrypt & Upload
              </button>

              <p className="notice">
                Your file is encrypted <strong>in this browser</strong> before it ever leaves your device.
                The server has zero knowledge of the content or key.
              </p>
            </div>
          )}
        </>
      )}

      {/* ── Encrypting / Uploading Progress ── */}
      {(status === 'encrypting' || status === 'uploading') && (
        <div className="progress-panel">
          <div className="progress-icon">
            {status === 'encrypting' ? '🔐' : '☁️'}
          </div>
          <h3>{status === 'encrypting' ? 'Encrypting in your browser...' : 'Uploading encrypted blob...'}</h3>
          <p className="progress-sub">
            {status === 'encrypting'
              ? 'AES-256-GCM is running client-side. Nothing has left your device yet.'
              : 'The server receives only encrypted gibberish. It has no key.'}
          </p>
          <div className="progress-bar">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <p className="progress-pct">{progress}%</p>
        </div>
      )}

      {/* ── Success: Share Link ── */}
      {status === 'done' && (
        <div className="success-panel">
          <div className="success-icon">✅</div>
          <h3>File encrypted & uploaded</h3>
          <p className="success-sub">
            Share the link below. {mode === 'auto'
              ? 'The decryption key is embedded after the #.'
              : 'Send the password separately through a different channel.'}
          </p>
          <div className="share-url-box">
            <code className="share-url">{shareURL}</code>
            <button className="btn-copy" onClick={handleCopy}>
              {copied ? '✓ Copied!' : '⧉ Copy'}
            </button>
          </div>
          {mode === 'password' && (
            <div className="warning-box">
              ⚠️ <strong>Send the password separately</strong> — via Signal, in person, or through a different channel.
              Never include the password in the same message as the link.
            </div>
          )}
          <button className="btn-ghost" onClick={handleReset}>
            ↩ Upload another file
          </button>
        </div>
      )}

      {/* ── Error ── */}
      {status === 'error' && (
        <div className="error-panel">
          <div className="error-icon">❌</div>
          <h3>Something went wrong</h3>
          <p>{errorMsg}</p>
          <button className="btn-primary" onClick={handleReset}>Try again</button>
        </div>
      )}

    </div>
  );
}
