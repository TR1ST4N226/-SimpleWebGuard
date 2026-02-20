const validator = require('validator');
const Logger = require('./logger');

/**
 * Input validation utilities
 */
class Validator {
  /**
   * Validate and normalize URL
   * @param {string} url - URL to validate
   * @returns {string|null} - Normalized URL or null if invalid
   */
  static validateURL(url) {
    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    // Validate URL format
    if (!validator.isURL(url, { 
      protocols: ['http', 'https'],
      require_protocol: true,
      require_valid_protocol: true
    })) {
      Logger.error('Invalid URL format. Please provide a valid URL.');
      return null;
    }

    return url;
  }

  /**
   * Validate port number
   * @param {number} port - Port to validate
   * @returns {boolean}
   */
  static validatePort(port) {
    return validator.isPort(String(port));
  }

  /**
   * Validate IP address
   * @param {string} ip - IP to validate
   * @returns {boolean}
   */
  static validateIP(ip) {
    return validator.isIP(ip);
  }
}

module.exports = Validator;
