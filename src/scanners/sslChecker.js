const https = require('https');
const tls = require('tls');
const { URL } = require('url');
const axios = require('axios');
const Logger = require('../utils/logger');

/**
 * SSL/TLS Certificate Checker
 */
class SSLChecker {
  /**
   * Analyze SSL/TLS configuration
   * @param {string} url - Target URL
   */
  static async scan(url) {
    Logger.section('SSL/TLS Configuration');

    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname;
      const port = parsedUrl.port || 443;

      // Check if HTTPS is used
      if (parsedUrl.protocol !== 'https:') {
        Logger.result('HTTPS', 'Not used', false);
        Logger.vulnerability('critical', 'Site is not using HTTPS. All traffic is unencrypted!');
        
        // Check if HTTP redirects to HTTPS
        await this.checkHTTPSRedirect(hostname);
        return;
      }

      Logger.result('HTTPS', 'Enabled', true);

      // Get certificate information
      await this.checkCertificate(hostname, port);

    } catch (error) {
      Logger.error(`Failed to check SSL/TLS: ${error.message}`);
    }
  }

  /**
   * Check if HTTP redirects to HTTPS
   */
  static async checkHTTPSRedirect(hostname) {
    try {
      const response = await axios.get(`http://${hostname}`, {
        maxRedirects: 0,
        validateStatus: (status) => status >= 200 && status < 400,
        timeout: 5000,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false
        })
      });

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.location;
        if (location && location.startsWith('https://')) {
          Logger.result('HTTP → HTTPS Redirect', 'Present', true);
        } else {
          Logger.result('HTTP → HTTPS Redirect', 'Incorrect', false);
          Logger.vulnerability('high', 'HTTP redirect exists but does not redirect to HTTPS');
        }
      }
    } catch (error) {
      if (error.response && error.response.status >= 300 && error.response.status < 400) {
        const location = error.response.headers.location;
        if (location && location.startsWith('https://')) {
          Logger.result('HTTP → HTTPS Redirect', 'Present', true);
        }
      } else {
        Logger.result('HTTP → HTTPS Redirect', 'Not configured', false);
        Logger.vulnerability('high', 'No automatic redirect from HTTP to HTTPS. Users may browse insecurely.');
      }
    }
  }

  /**
   * Check SSL certificate details
   */
  static async checkCertificate(hostname, port) {
    return new Promise((resolve) => {
      const options = {
        host: hostname,
        port: port,
        method: 'GET',
        rejectUnauthorized: false, // Allow self-signed for analysis
        agent: false
      };

      const req = https.request(options, (res) => {
        const cert = res.socket.getPeerCertificate();
        
        if (cert && Object.keys(cert).length > 0) {
          // Certificate validity
          this.checkCertificateValidity(cert);

          // Certificate issuer
          this.checkCertificateIssuer(cert);

          // Certificate subject
          this.checkCertificateSubject(cert, hostname);

          // Cipher and protocol
          this.checkCipherInfo(res.socket);
        } else {
          Logger.error('Could not retrieve certificate information');
        }

        resolve();
      });

      req.on('error', (error) => {
        Logger.error(`SSL/TLS connection failed: ${error.message}`);
        resolve();
      });

      req.end();
    });
  }

  /**
   * Check certificate validity period
   */
  static checkCertificateValidity(cert) {
    const now = new Date();
    const validFrom = new Date(cert.valid_from);
    const validTo = new Date(cert.valid_to);

    if (now < validFrom) {
      Logger.result('Certificate Status', 'Not yet valid', false);
      Logger.vulnerability('critical', `Certificate is not valid until ${validFrom.toDateString()}`);
    } else if (now > validTo) {
      Logger.result('Certificate Status', 'Expired', false);
      Logger.vulnerability('critical', `Certificate expired on ${validTo.toDateString()}`);
    } else {
      Logger.result('Certificate Status', 'Valid', true);
      
      // Check expiration warning (30 days)
      const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
      Logger.info(`  Valid until: ${validTo.toDateString()} (${daysUntilExpiry} days remaining)`);
      
      if (daysUntilExpiry < 30) {
        Logger.vulnerability('medium', `Certificate expires soon (${daysUntilExpiry} days). Renew it.`);
      }
    }
  }

  /**
   * Check certificate issuer
   */
  static checkCertificateIssuer(cert) {
    const issuer = cert.issuer;
    
    if (issuer) {
      const issuerName = issuer.CN || issuer.O || 'Unknown';
      Logger.result('Certificate Issuer', issuerName, true);

      // Check for self-signed
      if (cert.issuer.CN === cert.subject.CN) {
        Logger.vulnerability('high', 'Certificate is self-signed. Browsers will show security warnings.');
      } else {
        // Recognize trusted CAs
        const trustedCAs = ['Let\'s Encrypt', 'DigiCert', 'Comodo', 'GeoTrust', 'GlobalSign', 'Sectigo'];
        const isTrusted = trustedCAs.some(ca => issuerName.includes(ca));
        
        if (isTrusted) {
          Logger.info('  Issued by a recognized Certificate Authority ✓');
        }
      }
    }
  }

  /**
   * Check certificate subject and hostname match
   */
  static checkCertificateSubject(cert, hostname) {
    const subject = cert.subject;
    const subjectCN = subject.CN;
    
    if (subjectCN) {
      Logger.result('Certificate Subject', subjectCN, true);
      
      // Check hostname match
      if (subjectCN === hostname || this.wildcardMatch(subjectCN, hostname)) {
        Logger.info('  Certificate matches hostname ✓');
      } else {
        Logger.vulnerability('high', `Certificate CN (${subjectCN}) does not match hostname (${hostname})`);
      }
    }
  }

  /**
   * Check cipher and TLS version
   */
  static checkCipherInfo(socket) {
    const cipher = socket.getCipher();
    const protocol = socket.getProtocol();

    if (cipher) {
      Logger.result('Cipher Suite', cipher.name, true);
      Logger.info(`  Protocol: ${protocol}`);
      Logger.info(`  Encryption: ${cipher.standardName || cipher.name}`);

      // Check TLS version
      if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
        Logger.vulnerability('high', `Weak TLS version detected (${protocol}). Upgrade to TLS 1.2 or 1.3`);
      } else if (protocol === 'TLSv1.2' || protocol === 'TLSv1.3') {
        Logger.info(`  TLS version is secure (${protocol}) ✓`);
      }
    }
  }

  /**
   * Helper: Check wildcard certificate match
   */
  static wildcardMatch(certName, hostname) {
    if (certName.startsWith('*.')) {
      const domain = certName.substring(2);
      return hostname.endsWith(domain);
    }
    return false;
  }
}

module.exports = SSLChecker;
