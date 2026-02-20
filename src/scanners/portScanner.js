const net = require('net');
const { URL } = require('url');
const Logger = require('../utils/logger');

/**
 * TCP Port Scanner
 */
class PortScanner {
  /**
   * Scan common ports on target
   * @param {string} url - Target URL
   */
  static async scan(url) {
    Logger.section('Port Scanning');

    try {
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname;

      Logger.info(`Scanning common ports on ${hostname}...`);
      Logger.info('This may take a moment...\n');

      // Common ports to scan
      const commonPorts = [
        { port: 21, service: 'FTP', risk: 'high' },
        { port: 22, service: 'SSH', risk: 'medium' },
        { port: 23, service: 'Telnet', risk: 'critical' },
        { port: 25, service: 'SMTP', risk: 'medium' },
        { port: 80, service: 'HTTP', risk: 'low' },
        { port: 443, service: 'HTTPS', risk: 'low' },
        { port: 3306, service: 'MySQL', risk: 'high' },
        { port: 5432, service: 'PostgreSQL', risk: 'high' },
        { port: 6379, service: 'Redis', risk: 'high' },
        { port: 27017, service: 'MongoDB', risk: 'high' },
        { port: 3389, service: 'RDP', risk: 'high' },
        { port: 8080, service: 'HTTP-Alt', risk: 'low' },
        { port: 8443, service: 'HTTPS-Alt', risk: 'low' }
      ];

      const results = await this.scanPorts(hostname, commonPorts);
      this.displayResults(results);

    } catch (error) {
      Logger.error(`Failed to scan ports: ${error.message}`);
    }
  }

  /**
   * Scan multiple ports
   */
  static async scanPorts(hostname, ports) {
    const scanPromises = ports.map(portInfo => 
      this.checkPort(hostname, portInfo.port, portInfo.service, portInfo.risk)
    );

    return await Promise.all(scanPromises);
  }

  /**
   * Check if a single port is open
   */
  static checkPort(hostname, port, service, risk) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      const timeout = 2000; // 2 seconds timeout

      socket.setTimeout(timeout);

      socket.on('connect', () => {
        socket.destroy();
        resolve({ port, service, risk, open: true });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ port, service, risk, open: false });
      });

      socket.on('error', () => {
        socket.destroy();
        resolve({ port, service, risk, open: false });
      });

      socket.connect(port, hostname);
    });
  }

  /**
   * Display scan results
   */
  static displayResults(results) {
    const openPorts = results.filter(r => r.open);
    const closedPorts = results.filter(r => !r.open);

    if (openPorts.length === 0) {
      Logger.info('No common vulnerable ports detected (Good!)');
      return;
    }

    Logger.info(`Found ${openPorts.length} open port(s):\n`);

    // Group by risk level
    const criticalPorts = openPorts.filter(p => p.risk === 'critical');
    const highPorts = openPorts.filter(p => p.risk === 'high');
    const mediumPorts = openPorts.filter(p => p.risk === 'medium');
    const lowPorts = openPorts.filter(p => p.risk === 'low');

    // Display critical
    if (criticalPorts.length > 0) {
      criticalPorts.forEach(portInfo => {
        Logger.result(`Port ${portInfo.port}`, `${portInfo.service} - OPEN`, false);
        Logger.vulnerability('critical', this.getPortAdvice(portInfo.port, portInfo.service));
      });
    }

    // Display high
    if (highPorts.length > 0) {
      highPorts.forEach(portInfo => {
        Logger.result(`Port ${portInfo.port}`, `${portInfo.service} - OPEN`, false);
        Logger.vulnerability('high', this.getPortAdvice(portInfo.port, portInfo.service));
      });
    }

    // Display medium
    if (mediumPorts.length > 0) {
      mediumPorts.forEach(portInfo => {
        Logger.result(`Port ${portInfo.port}`, `${portInfo.service} - OPEN`, false);
        Logger.vulnerability('medium', this.getPortAdvice(portInfo.port, portInfo.service));
      });
    }

    // Display low (informational)
    if (lowPorts.length > 0) {
      Logger.info('\n  Standard web ports (informational):');
      lowPorts.forEach(portInfo => {
        Logger.result(`Port ${portInfo.port}`, `${portInfo.service} - OPEN`, true);
      });
    }
  }

  /**
   * Get security advice for specific ports
   */
  static getPortAdvice(port, service) {
    const advice = {
      21: 'FTP port is open. FTP transmits credentials in plaintext. Use SFTP (port 22) instead.',
      22: 'SSH port is open. Ensure strong passwords/keys are used and consider changing default port.',
      23: 'Telnet port is OPEN! Telnet is extremely insecure (plaintext). Disable immediately and use SSH.',
      25: 'SMTP port is open. Ensure it\'s properly configured to prevent spam relay.',
      3306: 'MySQL database port is exposed to the internet. Restrict access to trusted IPs only!',
      5432: 'PostgreSQL database port is exposed. Databases should NOT be publicly accessible!',
      6379: 'Redis port is exposed. Redis has no authentication by default. Restrict access immediately!',
      27017: 'MongoDB port is exposed. Databases should be behind a firewall, not public!',
      3389: 'RDP (Remote Desktop) is exposed. This is a common attack vector. Restrict to VPN only!',
      8080: 'Alternative HTTP port is open. Ensure this service is intentional and secured.',
      8443: 'Alternative HTTPS port is open. Ensure this service is intentional and secured.'
    };

    return advice[port] || `Port ${port} (${service}) is open. Verify if this exposure is necessary.`;
  }
}

module.exports = PortScanner;
