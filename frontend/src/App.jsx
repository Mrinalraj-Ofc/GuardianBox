/**
 * App.jsx — GuardianBox Root Application
 */
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom';
import Landing      from './components/Landing.jsx';
import UploadPage   from './components/UploadPage.jsx';
import DownloadPage from './components/DownloadPage.jsx';
import './App.css';

function Navbar() {
  return (
    <nav className="navbar">
      <NavLink to="/" className="nav-brand">
        <span className="brand-icon">🛡️</span>
        <span className="brand-text">GuardianBox</span>
        <span className="brand-tag">E2EE</span>
      </NavLink>
      <div className="nav-links">
        <NavLink to="/upload" className={({ isActive }) => isActive ? 'nav-link active' : 'nav-link'}>
          Upload
        </NavLink>
        <a
          href="https://github.com/your-username/guardianbox"
          target="_blank"
          rel="noopener noreferrer"
          className="nav-link"
        >
          GitHub
        </a>
      </div>
    </nav>
  );
}

function Footer() {
  return (
    <footer className="footer">
      <p>
        GuardianBox · AES-256-GCM · PBKDF2 · Web Crypto API ·{' '}
        <strong>Zero knowledge by design</strong>
      </p>
    </footer>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <div className="app">
        <Navbar />
        <main className="main-content">
          <Routes>
            <Route path="/"           element={<Landing />}      />
            <Route path="/upload"     element={<UploadPage />}   />
            <Route path="/file/:fileId" element={<DownloadPage />} />
          </Routes>
        </main>
        <Footer />
      </div>
    </BrowserRouter>
  );
}
