/**
 * DownloadPage.jsx — GuardianBox Download & Decryption UI
 * ────────────────────────────────────────────────────────
 * Opened when a recipient follows a share link:
 *   https://guardianbox.app/file/FILE_ID#auto:BASE64_KEY
 *
 * The # fragment never travels to the server.
 * This component reads it, fetches the encrypted blob,
 * decrypts entirely in the browser, and triggers a local download.
 */

import { useState, useEffect } from 'react';
import { useParams }            from 'react-router-dom';
import {
  decryptFile,
  parseURLFragment,
  triggerDownload,
} from '../utils/cryptoUtils.js';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:4000/api';

function formatBytes(b) {
  if (!b) return '—';
  const k = 1024, s = ['B','KB','MB','GB'];
  const i = Math.floor(Math.log(b) / Math.log(k));
  return `${(b / Math.pow(k, i)).toFixed(2)} ${s[i]}`;
}

function formatExpiry(iso) {
  if (!iso) return 'Never';
  const d = new Date(iso);
  return d.toLocaleString();
}

export default function DownloadPage() {
  const { fileId } = useParams();

  // Parsed from the URL fragment
  const [fragMode,  setFragMode]  = useState(null);   // 'auto' | 'password'
  const [fragKey,   setFragKey]   = useState('');     // key or empty

  // File metadata from the server
  const [meta,      setMeta]      = useState(null);

  // User inputs (password mode)
  const [password,  setPassword]  = useState('');

  // UI state
  const [status,    setStatus]    = useState('loading'); // loading|ready|decrypting|done|error
  const [errorMsg,  setErrorMsg]  = useState('');

  // ── On mount: parse fragment + fetch metadata ────────────────────────────

  useEffect(() => {
    // Parse the URL fragment (#mode:secret)
    const parsed = parseURLFragment(window.location.hash);

    if (!parsed) {
      setStatus('error');
      setErrorMsg('No decryption key found in the link. The URL may be incomplete.');
      return;
    }

    setFragMode(parsed.mode);
    // In auto mode: secret IS the key. In password mode: secret is ignored.
    if (parsed.mode === 'auto') setFragKey(parsed.secret);

    // Fetch file metadata from the server
    fetch(`${API_BASE}/files/${fileId}/meta`)
      .then((res) => {
        if (!res.ok) throw new Error('File not found or has expired.');
        return res.json();
      })
      .then((data) => {
        setMeta(data);
        setStatus('ready');
      })
      .catch((err) => {
        setStatus('error');
        setErrorMsg(err.message);
      });
  }, [fileId]);

  // ── Decrypt + Download ───────────────────────────────────────────────────

  const handleDecrypt = async () => {
    if (fragMode === 'password' && !password) {
      setErrorMsg('Please enter the decryption password.');
      return;
    }
    setErrorMsg('');
    setStatus('decrypting');

    try {
      // 1. Fetch the encrypted blob from the server
      const blobRes = await fetch(`${API_BASE}/files/${fileId}`);
      if (!blobRes.ok) {
        const body = await blobRes.json().catch(() => ({}));
        throw new Error(body.error || 'Failed to fetch encrypted file.');
      }
      const encryptedBuffer = await blobRes.arrayBuffer();

      // 2. Decrypt entirely in the browser
      const decrypted = await decryptFile(encryptedBuffer, {
        mode:     fragMode,
        keyB64:   fragMode === 'auto' ? fragKey : undefined,
        password: fragMode === 'password' ? password : undefined,
      });

      // 3. Trigger browser download of the original file
      triggerDownload(decrypted, meta.filename, meta.mimetype);
      setStatus('done');

    } catch (err) {
      console.error('[DECRYPT ERROR]', err);
      setStatus('error');
      setErrorMsg(err.message);
    }
  };

  // ── Render ───────────────────────────────────────────────────────────────

  if (status === 'loading') {
    return (
      <div className="download-page">
        <div className="loading-panel">
          <div className="spinner" />
          <p>Fetching file metadata…</p>
        </div>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="download-page">
        <div className="error-panel">
          <div className="error-icon">❌</div>
          <h3>Cannot retrieve file</h3>
          <p>{errorMsg}</p>
          <p className="sub-text">
            The file may have expired, reached its download limit, or the link is malformed.
          </p>
        </div>
      </div>
    );
  }

  if (status === 'decrypting') {
    return (
      <div className="download-page">
        <div className="progress-panel">
          <div className="progress-icon">🔓</div>
          <h3>Decrypting in your browser…</h3>
          <p className="progress-sub">
            AES-256-GCM is running locally. The key never left your device.
          </p>
          <div className="progress-bar">
            <div className="progress-fill indeterminate" />
          </div>
        </div>
      </div>
    );
  }

  if (status === 'done') {
    return (
      <div className="download-page">
        <div className="success-panel">
          <div className="success-icon">✅</div>
          <h3>File decrypted successfully</h3>
          <p className="success-sub">
            Your download should have started. If not, try refreshing.
          </p>
          {meta?.maxDownloads === 1 && (
            <div className="warning-box">
              🔥 This was a <strong>burn-after-reading</strong> link — the file has now been permanently deleted from the server.
            </div>
          )}
        </div>
      </div>
    );
  }

  // status === 'ready'
  return (
    <div className="download-page">
      <div className="download-panel">

        {/* File Card */}
        <div className="file-card">
          <div className="file-card-icon">📄</div>
          <div className="file-card-info">
            <p className="file-card-name">{meta?.filename}</p>
            <p className="file-card-meta">
              {meta?.mimetype} · {formatBytes(meta?.fileSizeBytes)}
            </p>
          </div>
          <div className="file-card-badge">🔒 Encrypted</div>
        </div>

        {/* Metadata */}
        <div className="meta-grid">
          <div className="meta-item">
            <span className="meta-key">Expires</span>
            <span className="meta-val">{formatExpiry(meta?.expiresAt)}</span>
          </div>
          <div className="meta-item">
            <span className="meta-key">Downloads</span>
            <span className="meta-val">
              {meta?.downloadCount ?? 0}
              {meta?.maxDownloads ? ` / ${meta.maxDownloads}` : ' / ∞'}
            </span>
          </div>
          <div className="meta-item">
            <span className="meta-key">Mode</span>
            <span className="meta-val">
              {fragMode === 'auto' ? '🔑 Auto-key' : '🔐 Password'}
            </span>
          </div>
        </div>

        {/* Password input (only for password mode) */}
        {fragMode === 'password' && (
          <div className="password-section">
            <label className="option-label">Decryption Password</label>
            <input
              className="text-input"
              type="password"
              placeholder="Enter the password provided by the sender…"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleDecrypt()}
              autoFocus
            />
          </div>
        )}

        {errorMsg && <p className="error-msg">⚠ {errorMsg}</p>}

        {/* Security Badge */}
        <div className="security-note">
          🛡️ Decryption happens <strong>entirely in this browser</strong>.
          The server never sees the key or your file contents.
        </div>

        <button className="btn-primary" onClick={handleDecrypt}>
          🔓 Decrypt & Download
        </button>

      </div>
    </div>
  );
}
