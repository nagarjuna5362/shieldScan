import React, { useState } from 'react';
import emailjs from '@emailjs/browser';

const SERVICE_ID = import.meta.env.VITE_EMAILJS_SERVICE_ID || 'service_scdpp7p';
const TEMPLATE_ID = import.meta.env.VITE_EMAILJS_TEMPLATE_ID || 'template_7nhspo9';
const PUBLIC_KEY = import.meta.env.VITE_EMAILJS_PUBLIC_KEY || 'Z8m-cZALjWLNN6L4Q';

export default function ContactModal({ onClose }) {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [issue, setIssue] = useState('');
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState({ show: false, message: '', type: 'success' });

  const showToast = (message, type = 'success') => {
    setToast({ show: true, message, type });
    setTimeout(() => {
      setToast(prev => ({ ...prev, show: false }));
    }, 4000);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (loading) return; // Prevent duplicate submissions

    const trimmedName = name.trim();
    const trimmedEmail = email.trim();
    const trimmedMessage = issue.trim();

    // Validations
    if (!trimmedName) {
      showToast('Name is required.', 'error');
      return;
    }
    if (!trimmedEmail) {
      showToast('Email address is required.', 'error');
      return;
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(trimmedEmail)) {
      showToast('Please enter a valid email address.', 'error');
      return;
    }
    if (!trimmedMessage) {
      showToast('Message is required.', 'error');
      return;
    }
    if (trimmedMessage.length > 2000) {
      showToast('Message cannot exceed 2000 characters.', 'error');
      return;
    }

    setLoading(true);

    try {
      const templateParams = {
        from_name: trimmedName,
        from_email: trimmedEmail,
        message: trimmedMessage,
      };

      const result = await emailjs.send(
        SERVICE_ID,
        TEMPLATE_ID,
        templateParams,
        PUBLIC_KEY
      );

      if (result.status !== 200) {
        throw new Error('Failed to deliver message via EmailJS');
      }

      showToast('Support request sent successfully.', 'success');
      
      // Reset form fields
      setName('');
      setEmail('');
      setIssue('');
    } catch (err) {
      console.error('EmailJS Error:', err);
      showToast('Support request failed to send. Please try again.', 'error');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(0, 0, 0, 0.7)',
      backdropFilter: 'blur(8px)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000,
      padding: '24px',
      fontFamily: "'Outfit', sans-serif"
    }} onClick={onClose}>
      <div style={{
        width: '100%',
        maxWidth: '480px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: '12px',
        padding: '32px',
        boxShadow: 'var(--shadow-lg)',
        boxSizing: 'border-box',
        position: 'relative',
        animation: 'pageEnter 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards',
        display: 'flex',
        flexDirection: 'column',
        gap: '20px'
      }} onClick={(e) => e.stopPropagation()}>
        {/* Close Button */}
        <button
          onClick={onClose}
          className="interactive-element"
          style={{
            position: 'absolute',
            top: '20px',
            right: '20px',
            background: 'none',
            border: 'none',
            fontSize: '18px',
            color: 'var(--text-muted)',
            cursor: 'pointer',
            padding: '4px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            transition: 'color 0.2s ease',
          }}
          aria-label="Close"
          onMouseEnter={(e) => e.target.style.color = 'var(--text-primary)'}
          onMouseLeave={(e) => e.target.style.color = 'var(--text-muted)'}
        >
          ✕
        </button>

        {/* Header */}
        <div>
          <h2 style={{
            fontSize: '22px',
            fontWeight: 900,
            color: 'var(--text-primary)',
            margin: '0 0 6px 0',
            letterSpacing: '-0.02em'
          }}>Contact Support</h2>
          <p style={{
            color: 'var(--text-secondary)',
            fontSize: '13px',
            lineHeight: 1.5,
            margin: 0
          }}>
            Submit your name, email, and description of the issue. A report will be sent directly to nagarjuna2005reddy@gmail.com.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Name Field */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: "'Space Mono', monospace" }}>Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your full name"
              required
              disabled={loading}
              style={{
                background: 'var(--input-bg)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '10px 14px',
                fontSize: '14px',
                color: 'var(--text-primary)',
                outline: 'none',
                transition: 'border-color 0.2s ease',
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--red)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            />
          </div>

          {/* Email Field */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: "'Space Mono', monospace" }}>Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@example.com"
              required
              disabled={loading}
              style={{
                background: 'var(--input-bg)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '10px 14px',
                fontSize: '14px',
                color: 'var(--text-primary)',
                outline: 'none',
                transition: 'border-color 0.2s ease',
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--red)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            />
          </div>

          {/* Issue Description Field */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            <label style={{ fontSize: '11px', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', fontFamily: "'Space Mono', monospace" }}>Describe the Issue</label>
            <textarea
              value={issue}
              onChange={(e) => setIssue(e.target.value)}
              placeholder="Describe what went wrong, your suggestion, or scanner question..."
              required
              disabled={loading}
              rows={4}
              maxLength={2000}
              style={{
                background: 'var(--input-bg)',
                border: '1px solid var(--border)',
                borderRadius: '8px',
                padding: '10px 14px',
                fontSize: '14px',
                color: 'var(--text-primary)',
                outline: 'none',
                resize: 'none',
                lineHeight: 1.5,
                transition: 'border-color 0.2s ease',
              }}
              onFocus={(e) => e.target.style.borderColor = 'var(--red)'}
              onBlur={(e) => e.target.style.borderColor = 'var(--border)'}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', fontSize: '10px', color: 'var(--text-muted)' }}>
              {issue.length}/2000 characters
            </div>
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className={loading ? "" : "btn-primary interactive-element"}
            style={{
              padding: '12px 24px',
              border: 'none',
              borderRadius: '8px',
              background: loading ? 'var(--border)' : 'var(--red)',
              color: loading ? 'var(--text-muted)' : '#ffffff',
              fontSize: '14px',
              fontWeight: 700,
              cursor: loading ? 'not-allowed' : 'pointer',
              fontFamily: "'Space Mono', monospace",
              transition: 'all 0.2s ease',
              textAlign: 'center',
              marginTop: '4px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '8px',
              boxShadow: loading ? 'none' : '0 4px 12px rgba(224, 41, 41, 0.2)'
            }}
          >
            {loading ? (
              <>
                <span style={{
                  display: 'inline-block',
                  width: '16px',
                  height: '16px',
                  border: '2px solid rgba(255, 255, 255, 0.3)',
                  borderTopColor: 'var(--red)',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }} />
                SENDING REPORT...
              </>
            ) : 'SEND REPORT'}
          </button>
        </form>
      </div>

      {/* Custom Toast Notification */}
      {toast.show && (
        <div style={{
          position: 'fixed',
          bottom: '24px',
          right: '24px',
          background: toast.type === 'success' ? '#22c55e' : '#ef4444',
          color: '#ffffff',
          padding: '12px 24px',
          borderRadius: '8px',
          boxShadow: 'var(--shadow-lg)',
          zIndex: 2000,
          fontFamily: "'Space Mono', monospace",
          fontSize: '12px',
          fontWeight: 700,
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          animation: 'slideInLeft 0.3s cubic-bezier(0.16, 1, 0.3, 1) forwards'
        }}>
          <span>{toast.type === 'success' ? '✓' : '⚠️'}</span>
          <span>{toast.message}</span>
        </div>
      )}
    </div>
  );
}
