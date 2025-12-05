// session-manager.js - Frontend SSO Session Manager
// Handles 30-minute timeout with 3-minute warning across all SYML services

class SymlSessionManager {
  constructor() {
    this.sessionId = this.getSessionFromCookie();
    this.heartbeatInterval = null;
    this.warningShown = false;
    this.warningTimer = null;
    this.logoutTimer = null;
    this.isActive = true;
    
    // Activity tracking
    this.lastActivity = Date.now();
    this.activityEvents = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
    
    this.init();
  }

  init() {
    if (!this.sessionId) {
      this.redirectToLogin();
      return;
    }

    // Start session monitoring
    this.startHeartbeat();
    this.bindActivityListeners();
    this.validateSession();
  }

  getSessionFromCookie() {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'syml_session') {
        return value;
      }
    }
    return null;
  }

  bindActivityListeners() {
    this.activityEvents.forEach(event => {
      document.addEventListener(event, () => {
        this.lastActivity = Date.now();
        this.isActive = true;
      }, true);
    });

    // Page visibility change
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        this.lastActivity = Date.now();
        this.isActive = true;
        this.validateSession();
      }
    });
  }

  async validateSession(service = null) {
    try {
      const response = await fetch('https://auth.syml.ai/validate-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sessionId: this.sessionId,
          service: service || this.getCurrentService()
        })
      });

      const result = await response.json();

      if (!result.valid) {
        this.handleSessionExpired();
        return false;
      }

      // Handle warning if needed
      if (result.needsWarning && !this.warningShown) {
        this.showTimeoutWarning(result.timeRemaining);
      } else if (!result.needsWarning && this.warningShown) {
        this.hideTimeoutWarning();
      }

      return true;
    } catch (error) {
      console.error('Session validation failed:', error);
      this.handleSessionExpired();
      return false;
    }
  }

  getCurrentService() {
    const hostname = window.location.hostname;
    if (hostname.includes('statements')) return 'scan';
    if (hostname.includes('lms')) return 'lms';
    return 'main';
  }

  startHeartbeat() {
    // Check session every 5 minutes
    this.heartbeatInterval = setInterval(async () => {
      // Only validate if user has been active in last 5 minutes
      const timeSinceActivity = Date.now() - this.lastActivity;
      if (timeSinceActivity < 5 * 60 * 1000) {
        await this.validateSession();
      }
    }, 5 * 60 * 1000);
  }

  showTimeoutWarning(timeRemaining) {
    if (this.warningShown) return;
    
    this.warningShown = true;
    const minutes = Math.ceil(timeRemaining / (60 * 1000));

    // Create warning modal
    const modal = document.createElement('div');
    modal.id = 'syml-timeout-warning';
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0, 0, 0, 0.8);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 10000;
      font-family: 'Montserrat', sans-serif;
    `;

    modal.innerHTML = `
      <div style="
        background: white;
        padding: 2rem;
        border-radius: 12px;
        text-align: center;
        max-width: 400px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
      ">
        <div style="color: #FF6B35; font-size: 3rem; margin-bottom: 1rem;">⚠️</div>
        <h2 style="color: #36013F; margin-bottom: 1rem;">Session Timeout Warning</h2>
        <p style="color: #666; margin-bottom: 2rem;">
          Your session will expire in ${minutes} minute${minutes !== 1 ? 's' : ''}. 
          Click "Stay Logged In" to continue your session.
        </p>
        <div style="display: flex; gap: 1rem; justify-content: center;">
          <button id="syml-stay-logged-in" style="
            background: #106C6D;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
          ">Stay Logged In</button>
          <button id="syml-logout-now" style="
            background: #FF6B35;
            color: white;
            border: none;
            padding: 0.75rem 1.5rem;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 600;
          ">Logout Now</button>
        </div>
      </div>
    `;

    document.body.appendChild(modal);

    // Event listeners
    document.getElementById('syml-stay-logged-in').onclick = () => {
      this.refreshSession();
      this.hideTimeoutWarning();
    };

    document.getElementById('syml-logout-now').onclick = () => {
      this.logout();
    };

    // Auto-logout timer (3 minutes)
    this.logoutTimer = setTimeout(() => {
      this.logout();
    }, 3 * 60 * 1000);
  }

  hideTimeoutWarning() {
    const modal = document.getElementById('syml-timeout-warning');
    if (modal) {
      modal.remove();
    }
    
    this.warningShown = false;
    
    if (this.logoutTimer) {
      clearTimeout(this.logoutTimer);
      this.logoutTimer = null;
    }
  }

  async refreshSession() {
    try {
      const response = await fetch('https://auth.syml.ai/refresh-session', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sessionId: this.sessionId
        })
      });

      const result = await response.json();
      
      if (!result.valid) {
        this.handleSessionExpired();
      }
    } catch (error) {
      console.error('Session refresh failed:', error);
      this.handleSessionExpired();
    }
  }

  async logout() {
    try {
      await fetch('https://auth.syml.ai/logout', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          sessionId: this.sessionId
        })
      });
    } catch (error) {
      console.error('Logout request failed:', error);
    }

    this.cleanup();
    this.redirectToLogin();
  }

  handleSessionExpired() {
    this.cleanup();
    
    // Show expired message
    alert('Your session has expired. You will be redirected to login.');
    this.redirectToLogin();
  }

  redirectToLogin() {
    window.location.href = 'https://auth.syml.ai/login';
  }

  cleanup() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
    }
    
    if (this.logoutTimer) {
      clearTimeout(this.logoutTimer);
    }
    
    this.hideTimeoutWarning();
    
    // Remove activity listeners
    this.activityEvents.forEach(event => {
      document.removeEventListener(event, this.activityHandler, true);
    });
  }

  // Public method to check if session is valid
  async isSessionValid() {
    return await this.validateSession();
  }

  // Public method to get user info
  async getUserInfo() {
    const response = await fetch('https://auth.syml.ai/validate-session', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        sessionId: this.sessionId,
        service: this.getCurrentService()
      })
    });

    const result = await response.json();
    return result.valid ? {
      email: result.email,
      role: result.role,
      sessionId: result.sessionId
    } : null;
  }
}

// Auto-initialize session manager
window.symlSession = new SymlSessionManager();

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = SymlSessionManager;
}