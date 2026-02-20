#!/usr/bin/env node

const readline = require('readline');
const Logger = require('./utils/logger');
const Validator = require('./utils/validator');
const HeaderScanner = require('./scanners/headerScanner');
const ServerFingerprint = require('./scanners/serverFingerprint');
const SSLChecker = require('./scanners/sslChecker');
const PortScanner = require('./scanners/portScanner');

/**
 * SimpleWebGuard - Web Vulnerability Auditor
 * Black-box security scanner for web applications
 */
class SimpleWebGuard {
  /**
   * Main entry point
   */
  static async run() {
    this.displayBanner();

    // Get URL from command line or prompt
    let targetUrl = process.argv[2];

    if (!targetUrl) {
      targetUrl = await this.promptForURL();
    }

    // Validate URL
    const validatedUrl = Validator.validateURL(targetUrl);
    if (!validatedUrl) {
      process.exit(1);
    }

    Logger.info(`Target: ${validatedUrl}\n`);

    // Run all scanners
    await this.runScanners(validatedUrl);

    // Display summary
    this.displaySummary();
  }

  /**
   * Display banner
   */
  static displayBanner() {
    console.log('\n');
    console.log('═'.repeat(70));
    console.log('  🛡️  SimpleWebGuard - Web Vulnerability Auditor');
    console.log('  Black-Box Security Scanner for Web Applications');
    console.log('═'.repeat(70));
    console.log('\n');
  }

  /**
   * Prompt user for URL input
   */
  static promptForURL() {
    return new Promise((resolve) => {
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
      });

      rl.question('Enter target URL (e.g., https://example.com): ', (answer) => {
        rl.close();
        resolve(answer.trim());
      });
    });
  }

  /**
   * Run all security scanners
   */
  static async runScanners(url) {
    const startTime = Date.now();

    try {
      // 1. Server Fingerprinting
      await ServerFingerprint.scan(url);

      // 2. Security Headers Analysis
      await HeaderScanner.scan(url);

      // 3. SSL/TLS Configuration
      await SSLChecker.scan(url);

      // 4. Port Scanning
      await PortScanner.scan(url);

    } catch (error) {
      Logger.error(`Scan failed: ${error.message}`);
    }

    const endTime = Date.now();
    const duration = ((endTime - startTime) / 1000).toFixed(2);

    Logger.info(`\nScan completed in ${duration} seconds`);
  }

  /**
   * Display final summary
   */
  static displaySummary() {
    Logger.header('Scan Complete');
    console.log('📋 Review the findings above and take action on vulnerabilities.');
    console.log('');
    console.log('🔒 Security Recommendations:');
    console.log('  • Configure proper security headers (CSP, HSTS, X-Frame-Options)');
    console.log('  • Hide server version information');
    console.log('  • Use valid SSL/TLS certificates with strong ciphers');
    console.log('  • Close unnecessary ports and services');
    console.log('  • Implement firewall rules to restrict database access');
    console.log('');
    console.log('⚠️  Disclaimer: This tool performs passive reconnaissance only.');
    console.log('   Always obtain permission before scanning systems you don\'t own.');
    console.log('');
  }
}

// Run the application
if (require.main === module) {
  SimpleWebGuard.run().catch(error => {
    Logger.error(`Fatal error: ${error.message}`);
    process.exit(1);
  });
}

module.exports = SimpleWebGuard;
