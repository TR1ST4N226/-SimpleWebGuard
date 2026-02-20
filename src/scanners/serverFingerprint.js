const axios = require('axios');
const https = require('https');
const Logger = require('../utils/logger');

/**
 * Server Fingerprinting Scanner
 */
class ServerFingerprint {
  /**
   * Analyze server information from headers
   * @param {string} url - Target URL
   */
  static async scan(url) {
    Logger.section('Server Fingerprinting');

    try {
      const response = await axios.get(url, {
        validateStatus: () => true,
        maxRedirects: 5,
        timeout: 10000,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false
        })
      });

      const headers = response.headers;

      // Check Server header
      this.checkServerHeader(headers);

      // Check X-Powered-By header
      this.checkPoweredBy(headers);

      // Check other revealing headers
      this.checkOtherHeaders(headers);

    } catch (error) {
      Logger.error(`Failed to fetch server information: ${error.message}`);
    }
  }

  /**
   * Check Server header for version disclosure
   */
  static checkServerHeader(headers) {
    const server = headers['server'];
    
    if (server) {
      Logger.result('Server', server, false);
      
      // Check if version number is present
      const versionPattern = /\d+\.\d+/;
      if (versionPattern.test(server)) {
        Logger.vulnerability('medium', 'Server header discloses version information. This helps attackers find specific CVEs.');
        Logger.info('  Recommendation: Configure server to hide version (e.g., "nginx" instead of "nginx/1.18.0")');
      } else {
        Logger.info('  Server type is disclosed but version is hidden (Good practice)');
      }

      // Identify common servers
      this.identifyServer(server);
    } else {
      Logger.result('Server', 'Not disclosed', true);
      Logger.info('  Server header is hidden (Good security practice)');
    }
  }

  /**
   * Check X-Powered-By header
   */
  static checkPoweredBy(headers) {
    const poweredBy = headers['x-powered-by'];
    
    if (poweredBy) {
      Logger.result('X-Powered-By', poweredBy, false);
      Logger.vulnerability('medium', 'X-Powered-By header reveals backend technology. Remove this header.');
      
      // Identify technologies
      if (poweredBy.toLowerCase().includes('php')) {
        Logger.info('  Technology: PHP detected');
      } else if (poweredBy.toLowerCase().includes('asp')) {
        Logger.info('  Technology: ASP.NET detected');
      } else if (poweredBy.toLowerCase().includes('express')) {
        Logger.info('  Technology: Express.js detected');
      }
    } else {
      Logger.result('X-Powered-By', 'Not present', true);
      Logger.info('  X-Powered-By header is hidden (Good security practice)');
    }
  }

  /**
   * Check other information disclosure headers
   */
  static checkOtherHeaders(headers) {
    const revealingHeaders = [
      'x-aspnet-version',
      'x-aspnetmvc-version',
      'x-generator',
      'x-drupal-cache',
      'x-varnish',
      'via'
    ];

    let foundRevealing = false;

    for (const headerName of revealingHeaders) {
      if (headers[headerName]) {
        if (!foundRevealing) {
          Logger.info('\n  Other information disclosure headers:');
          foundRevealing = true;
        }
        Logger.vulnerability('low', `${headerName}: ${headers[headerName]}`);
      }
    }

    if (!foundRevealing) {
      Logger.info('  No other information disclosure headers found ✓');
    }
  }

  /**
   * Identify server type and provide insights
   */
  static identifyServer(server) {
    const serverLower = server.toLowerCase();
    
    if (serverLower.includes('nginx')) {
      Logger.info('  Detected: Nginx web server');
      Logger.info('  Common ports: 80, 443');
    } else if (serverLower.includes('apache')) {
      Logger.info('  Detected: Apache web server');
      Logger.info('  Common ports: 80, 443');
    } else if (serverLower.includes('iis') || serverLower.includes('microsoft')) {
      Logger.info('  Detected: Microsoft IIS');
      Logger.info('  Platform: Windows Server');
    } else if (serverLower.includes('cloudflare')) {
      Logger.info('  Detected: Cloudflare CDN/Proxy');
      Logger.info('  Note: Real server may be hidden behind Cloudflare');
    } else if (serverLower.includes('lighttpd')) {
      Logger.info('  Detected: Lighttpd web server');
    } else if (serverLower.includes('caddy')) {
      Logger.info('  Detected: Caddy web server');
    }
  }
}

module.exports = ServerFingerprint;
