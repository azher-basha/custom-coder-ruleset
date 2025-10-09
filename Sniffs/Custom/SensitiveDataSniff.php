<?php

namespace BIPractice\Sniffs\Custom;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Detects sensitive or risky data exposure in logger, watchdog, API, or debug contexts.
 *
 * Covers:
 * - Logging payloads or sensitive fields
 * - Printing or dumping sensitive info
 * - Returning sensitive fields in API responses
 * - Using debug output functions in production code
 */
class SensitiveDataSniff implements Sniff {

  /**
   * Sensitive variable names / functions / keywords to detect.
   */
  private $sensitiveVariables = [
    '$payload', '$post', '$get', '$data', '$request', '$response',
    '$_POST', '$_GET', '$_REQUEST', '$_SESSION', '$_COOKIE',
    '$user', '$account', '$password', '$token', '$auth', '$apikey',
  ];

  private $sensitiveFunctions = [
    'print_r', 'var_dump', 'var_export', 'debug', 'serialize', 'json_encode',
  ];

  private $sensitiveKeywords = [
    'password', 'token', 'secret', 'ssn', 'creditcard', 'card', 'apikey', 'auth',
  ];

  private $loggingFunctions = [
    'watchdog', 'info', 'notice', 'debug', 'error', 'alert', 'critical', 'emergency',
  ];

  /**
   * Returns list of token types to register.
   */
  public function register() {
    return [T_STRING, T_DOUBLE_COLON, T_OBJECT_OPERATOR];
  }

  /**
   * Processes tokens for sensitive data usage.
   */
  public function process(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $token = $tokens[$stackPtr];

    // Handle logger, watchdog, and debug detection
    if ($token['code'] === T_STRING) {
      $functionName = strtolower($token['content']);

      // Detect watchdog(), \Drupal::logger(), or $this->logger->*
      if (
        $functionName === 'watchdog' ||
        $this->isDrupalLoggerCall($phpcsFile, $stackPtr) ||
        $this->isObjectLoggerCall($phpcsFile, $stackPtr)
      ) {
        $this->checkLoggerArguments($phpcsFile, $stackPtr);
      }

      // Detect Sensitive Functions - debug or print functions.
      if (in_array($functionName, $this->sensitiveFunctions, TRUE)) {
        $phpcsFile->addError(
          sprintf('Use of "%s()" funtion is meant only for debugging or troubleshooting purposes. Avoid using it in production code.', $functionName),
          $stackPtr,
          'DebugFunctionUsage'
        );
      }

      // Detect Drupal Logger service type - debug or info functions.
      if (in_array($functionName, $this->loggingFunctions, TRUE)) {
        if (in_array($functionName, $this->sensitiveFunctions, TRUE)) {
          
        } else {
          $phpcsFile->addWarning(
          sprintf('Use of "%s()" funtion / Drupal Logger service log type may expose sensitive information.', $functionName),
          $stackPtr,
          'DebugFunctionUsage'
        );
        }
      }
    }

    // Detect echo or print statements.
    if (in_array($token['code'], [T_ECHO, T_PRINT], TRUE)) {
      $this->checkSensitiveVariables($phpcsFile, $stackPtr, 'Direct output of sensitive data detected.');
    }

    // Detect return statement leaking sensitive data.
    if ($token['code'] === T_RETURN) {
      $this->checkReturnForSensitiveData($phpcsFile, $stackPtr);
    }
  }

  /**
   * Detects \Drupal::logger() or Drupal::logger() static calls.
   */
  private function isDrupalLoggerCall(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $current = strtolower($tokens[$stackPtr]['content']);

    if ($current !== 'logger') {
      return FALSE;
    }

    // Check if previous tokens form "\Drupal::"
    $prev = $phpcsFile->findPrevious([T_DOUBLE_COLON, T_STRING, T_NS_SEPARATOR], $stackPtr - 1, null, false, null, true);
    if ($prev && strtolower($tokens[$prev]['content']) === 'drupal') {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Detects object logger calls like $this->logger->info() or $logger->error().
   */
  private function isObjectLoggerCall(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();

    // If current token is info/debug/error etc. check if part of $this->logger or $logger chain
    if (!in_array(strtolower($tokens[$stackPtr]['content']), $this->loggingFunctions, TRUE)) {
      return FALSE;
    }

    // Look back for "->logger"
    $prevObjOp = $phpcsFile->findPrevious(T_OBJECT_OPERATOR, $stackPtr - 1, null, false, null, true);
    if (!$prevObjOp) {
      return FALSE;
    }

    $prevString = $phpcsFile->findPrevious(T_STRING, $prevObjOp - 1, null, false, null, true);
    $prevVar = $phpcsFile->findPrevious(T_VARIABLE, $prevObjOp - 1, null, false, null, true);

    if (
      ($prevString && strtolower($tokens[$prevString]['content']) === 'logger') ||
      ($prevVar && in_array($tokens[$prevVar]['content'], ['$this', '$logger', '$log'], true))
    ) {
      return TRUE;
    }

    return FALSE;
  }

  /**
   * Inspect arguments passed to logger/watchdog.
   */
  private function checkLoggerArguments(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $openParenthesis = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr);
    $closeParenthesis = isset($tokens[$openParenthesis]['parenthesis_closer'])
      ? $tokens[$openParenthesis]['parenthesis_closer']
      : null;

    if (!$closeParenthesis) {
      return;
    }

    for ($i = $openParenthesis + 1; $i < $closeParenthesis; $i++) {
      $content = $tokens[$i]['content'];

      // Look for sensitive variable usage.
      foreach ($this->sensitiveVariables as $var) {
        if (stripos($content, $var) !== FALSE) {
          $phpcsFile->addError(
            sprintf('Drupal Logger service using "%s" variable. Avoid logging or passing direct variable values that may contain API payloads or PI data.', $var),
            $i,
            'SensitiveLoggerVariable'
          );
        }
      }

      // Look for sensitive keywords in string literals.
      if ($tokens[$i]['code'] === T_CONSTANT_ENCAPSED_STRING) {
        foreach ($this->sensitiveKeywords as $kw) {
          if (stripos($content, $kw) !== FALSE) {
            $phpcsFile->addWarning(
              sprintf('Drupal Logger service message contains the sensitive keyword "%s".', $kw),
              $i,
              'SensitiveLoggerKeyword'
            );
          }
        }
      }
    }
  }

  /**
   * Checks if a return statement or API output leaks sensitive data.
   */
  private function checkReturnForSensitiveData(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $line = $tokens[$stackPtr]['line'];

    for ($i = $stackPtr + 1; isset($tokens[$i]) && $tokens[$i]['line'] === $line; $i++) {
      $content = $tokens[$i]['content'];

      foreach ($this->sensitiveVariables as $var) {
        if (stripos($content, $var) !== FALSE) {
          $phpcsFile->addWarning(
            sprintf('Return statement may expose sensitive variable "%s" in API response.', $var),
            $i,
            'SensitiveApiReturn'
          );
        }
      }

      foreach ($this->sensitiveKeywords as $kw) {
        if (stripos($content, $kw) !== FALSE) {
          $phpcsFile->addWarning(
            sprintf('Returned data may contain sensitive field "%s".', $kw),
            $i,
            'SensitiveApiKeyword'
          );
        }
      }
    }
  }

  /**
   * Generalized check for sensitive variable or keyword usage.
   */
  private function checkSensitiveVariables(File $phpcsFile, $stackPtr, $message) {
    $tokens = $phpcsFile->getTokens();
    $line = $tokens[$stackPtr]['line'];

    for ($i = $stackPtr + 1; isset($tokens[$i]) && $tokens[$i]['line'] === $line; $i++) {
      $content = $tokens[$i]['content'];

      foreach ($this->sensitiveVariables as $var) {
        if (stripos($content, $var) !== FALSE) {
          $phpcsFile->addWarning($message, $i, 'SensitiveVariable');
        }
      }

      foreach ($this->sensitiveKeywords as $kw) {
        if (stripos($content, $kw) !== FALSE) {
          $phpcsFile->addWarning(
            sprintf('%s Keyword: "%s"', $message, $kw),
            $i,
            'SensitiveKeyword'
          );
        }
      }
    }
  }
}
