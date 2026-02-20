const chalk = require('chalk');

/**
 * Logger utility with colored output
 */
class Logger {
  /**
   * Display success message (green)
   */
  static success(message) {
    console.log(chalk.green('✓ ') + chalk.green.bold(message));
  }

  /**
   * Display error message (red)
   */
  static error(message) {
    console.log(chalk.red('✗ ') + chalk.red.bold(message));
  }

  /**
   * Display warning message (yellow)
   */
  static warning(message) {
    console.log(chalk.yellow('⚠ ') + chalk.yellow.bold(message));
  }

  /**
   * Display info message (blue)
   */
  static info(message) {
    console.log(chalk.blue('ℹ ') + chalk.blue(message));
  }

  /**
   * Display header message (cyan, bold)
   */
  static header(message) {
    console.log('\n' + chalk.cyan.bold('═'.repeat(60)));
    console.log(chalk.cyan.bold('  ' + message));
    console.log(chalk.cyan.bold('═'.repeat(60)) + '\n');
  }

  /**
   * Display section title
   */
  static section(message) {
    console.log('\n' + chalk.magenta.bold('▸ ' + message));
  }

  /**
   * Display result line (label + value)
   */
  static result(label, value, isGood = true) {
    const symbol = isGood ? chalk.green('✓') : chalk.red('✗');
    console.log(`  ${symbol} ${chalk.white(label)}: ${chalk.cyan(value)}`);
  }

  /**
   * Display vulnerability/issue
   */
  static vulnerability(severity, message) {
    const colors = {
      critical: chalk.red.bold,
      high: chalk.red,
      medium: chalk.yellow,
      low: chalk.blue,
      info: chalk.gray
    };
    const color = colors[severity] || chalk.white;
    console.log(`  ${chalk.red('⚠')} ${color(`[${severity.toUpperCase()}]`)} ${message}`);
  }
}

module.exports = Logger;
