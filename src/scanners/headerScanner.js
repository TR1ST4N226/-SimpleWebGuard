const axios = require('axios');
const https = require('https');
const Logger = require('../utils/logger');

/**
 * Security Headers Scanner
 */
class HeaderScanner {
  /**
   * Analyze security headers of a URL
   * @param {string} url - Target URL
   */
  static async scan(url) {
    Logger.section('Security Headers Analysis');

    try {
      const response = await axios.get(url, {
        validateStatus: () => true, // Accept all status codes
        maxRedirects: 5,
        timeout: 10000,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false // Allow self-signed certificates for testing
        })
      });

      const headers = response.headers;

      // Check Content-Security-Policy
      this.checkCSP(headers);

      // Check HSTS
      this.checkHSTS(headers);

      // Check X-Frame-Options
      this.checkXFrameOptions(headers);

      // Check X-Content-Type-Options
      this.checkXContentTypeOptions(headers);

      // Check X-XSS-Protection
      this.checkXSSProtection(headers);

      // Check Referrer-Policy
      this.checkReferrerPolicy(headers);

      // Check Permissions-Policy
      this.checkPermissionsPolicy(headers);

    } catch (error) {
      Logger.error(`Failed to fetch headers: ${error.message}`);
    }
  }

  /**
   * Check Content-Security-Policy header
   */
  static checkCSP(headers) {
    const csp = headers['content-security-policy'];
    if (csp) {
      Logger.result('Content-Security-Policy', 'Present', true);
      Logger.info(`  Value: ${csp.substring(0, 80)}${csp.length > 80 ? '...' : ''}`);
    } else {
      Logger.result('Content-Security-Policy', 'Missing', false);
      Logger.vulnerability('high', 'CSP header is missing. Site is vulnerable to XSS attacks.');
    }
  }

  /**
   * Check Strict-Transport-Security header
   */
  static checkHSTS(headers) {
    const hsts = headers['strict-transport-security'];
    if (hsts) {
      Logger.result('Strict-Transport-Security', 'Present', true);
      Logger.info(`  Value: ${hsts}`);
      
      // Check max-age value
      const maxAgeMatch = hsts.match(/max-age=(\d+)/);
      if (maxAgeMatch) {
        const maxAge = parseInt(maxAgeMatch[1]);
        const sixMonthsInSeconds = 15552000;
        
        if (maxAge < sixMonthsInSeconds) {
          Logger.vulnerability('medium', `HSTS max-age is too low (${maxAge}s). Recommended: at least 6 months (15552000s)`);
        }
      }
    } else {
      Logger.result('Strict-Transport-Security', 'Missing', false);
      Logger.vulnerability('high', 'HSTS header is missing. Site is vulnerable to protocol downgrade attacks.');
    }
  }

  /**
   * Check X-Frame-Options header
   */
  static checkXFrameOptions(headers) {
    const xFrameOptions = headers['x-frame-options'];
    if (xFrameOptions) {
      const value = xFrameOptions.toUpperCase();
      const isSecure = value === 'DENY' || value === 'SAMEORIGIN';
      Logger.result('X-Frame-Options', value, isSecure);
      
      if (!isSecure) {
        Logger.vulnerability('medium', 'X-Frame-Options is set but value is not secure.');
      }
    } else {
      Logger.result('X-Frame-Options', 'Missing', false);
      Logger.vulnerability('medium', 'X-Frame-Options header is missing. Site may be vulnerable to Clickjacking.');
    }
  }

  /**
   * Check X-Content-Type-Options header
   */
  static checkXContentTypeOptions(headers) {
    const xContentType = headers['x-content-type-options'];
    if (xContentType && xContentType.toLowerCase() === 'nosniff') {
      Logger.result('X-Content-Type-Options', 'nosniff', true);
    } else {
      Logger.result('X-Content-Type-Options', xContentType || 'Missing', false);
      Logger.vulnerability('low', 'X-Content-Type-Options header is missing or incorrect. Browser may interpret files incorrectly.');
    }
  }

  /**
   * Check X-XSS-Protection header
   */
  static checkXSSProtection(headers) {
    const xssProtection = headers['x-xss-protection'];
    if (xssProtection) {
      Logger.result('X-XSS-Protection', xssProtection, true);
    } else {
      Logger.result('X-XSS-Protection', 'Missing', false);
      Logger.vulnerability('info', 'X-XSS-Protection header is missing (deprecated but still useful for older browsers).');
    }
  }

  /**
   * Check Referrer-Policy header
   */
  static checkReferrerPolicy(headers) {
    const referrerPolicy = headers['referrer-policy'];
    if (referrerPolicy) {
      Logger.result('Referrer-Policy', referrerPolicy, true);
    } else {
      Logger.result('Referrer-Policy', 'Missing', false);
      Logger.vulnerability('low', 'Referrer-Policy header is missing. Referer information may leak.');
    }
  }

  /**
   * Check Permissions-Policy header
   */
  static checkPermissionsPolicy(headers) {
    const permissionsPolicy = headers['permissions-policy'] || headers['feature-policy'];
    if (permissionsPolicy) {
      Logger.result('Permissions-Policy', 'Present', true);
    } else {
      Logger.result('Permissions-Policy', 'Missing', false);
      Logger.vulnerability('info', 'Permissions-Policy header is missing. Consider restricting browser features.');
    }
  }
}

module.exports = HeaderScanner;
