<?php

namespace BIPractice\Sniffs\Custom;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;

/**
 * Detects sensitive or risky data exposure in logger, watchdog, API, or debug contexts.
 *
 * This sniff identifies potential security and code quality issues by detecting:
 * - Logging of sensitive data (passwords, tokens, API keys, etc.)
 * - Use of debugging functions in production code
 * - Direct output of sensitive information via echo/print
 * - Exposure of sensitive data in API return statements
 * - Declaration and usage of sensitive variables throughout the codebase
 * - Detection of hardcoded sensitive credentials during initialization.
 * - **NEW: General detection of any variable or array key initialized with hardcoded values,**
 *   to ensure developers review for potential hidden credentials.
 *
 * @package BIPractice\Sniffs\Custom
 */
class SensitiveDataSniff implements Sniff {

  /**
   * Sensitive variable names to detect in code.
   *
   * Add new sensitive variable patterns here. Variables should include the '$' prefix.
   * These are checked for exact matches in variable usage.
   *
   * @var string[]
   */
  private $sensitiveVariables = [
    // Request/Response data
    '$payload',
    '$post',
    '$get',
    '$data',
    '$request',
    '$response',
    '$api_response',
    '$api_request',
    
    // PHP superglobals
    '$_POST',
    '$_GET',
    '$_REQUEST',
    '$_SESSION',
    '$_COOKIE',
    
    // Authentication/User data
    '$user',
    '$username',
    '$account',
    '$password',
    '$token',
    '$auth',
    '$apikey',
    '$email',
    '$firstname',
    '$lastname',
    '$country',
    '$first_name',
    '$last_name',
    '$company_organization',
    '$job_title',
    '$business_purpose',
    '$required_information',
    '$license_number',
    '$identifier',
    '$identifier_type',
    '$country_code',
    '$auth0userid',
    '$loggedinuserid',
    '$auth_id',
    '$api_key',
    '$webinarId',
    '$Fname',
    '$Lname',
    '$veeva_id',
    '$custom_questions',
    '$address_value',
    '$productName',
    '$searchTerms',
    '$opu',
    '$state_licensed_in',
    '$address',
    '$zip_code',
    '$npi',
    '$state_license_id',
    '$latitude',
    '$longitude',
    '$botId',
  ];

  /**
   * Debugging functions that should be avoided in production code.
   *
   * Add new debugging function names here (lowercase).
   * These will trigger ERROR-level messages when detected.
   *
   * @var string[]
   */
  private $debugFunctions = [
    // Standard PHP debug functions
    'print_r',
    'var_dump',
    'var_export',
    'debug',
    
    // Data serialization (often used for debugging)
    'serialize',
    'json_encode',
    
    // Drupal-specific debug functions
    'dsm',
    'dpm',
    'kint',
    'ksm',
  ];

  /**
   * Keywords indicating sensitive information in strings.
   *
   * Add new sensitive keyword patterns here (lowercase).
   * These are checked using case-insensitive partial matching in string literals.
   *
   * @var string[]
   */
  private $sensitiveKeywords = [
    'password',
    'token',
    'secret',
    'ssn',
    'creditcard',
    'card',
    'apikey',
    'auth',
    'client_id',
    'client_secret',
    'access_token',
    'encryption_key',
    'Q_FIRSTNAME',
    'Q_LASTNAME',
    'Q_PHONE',
    'Q_MOBILE_PHONE',
    'Q_EMAIL',
    'Q_ADDRESS1',
    'Q_DOB',
    'EmailAddress',
    'EmailId',
    'FirstName',
    'MiddleName',
    'LastName',
    'Phones',
    'Phone',
    'PhoneNumber',
    'BirthDate',
    'PatientFirstName',
    'PatientLastName',
    'PatientAddress1',
    'PatientBirthDate',
    'PatientPhoneNumber',
    'PatientEmailAddress',
    'OpenDoors',
    'first_name',
    'last_name',
    'address',
    'apartment',
    'city',
    'state',
    'zipcode',
    'mobile',
    'dob',
    'ID_REQUEST',
    'Q_CAM_ID',
    'Q_SOURCE',
    'CARD_TYPE',
    'state_id',
    'info_self',
    'prescribed_spe',
    'insurance_type',
    'copay_enrollment',
    'bi_solution_patient_navigator_',
    'best_time_to_contact',
    'receive_periodic_communications',
    'share_your_story',
    'voice_mail',
    'copay_text_message_consent',
    'cg_guardian_first_name',
    'cg_guardian_last_name',
    'cg_guardian_phone',
    'alt_contact_permission',
    'cnsnt_patient_name',
    'cnsnt_patient_dob',
    'cnsnt_patient_email',
    'cnsnt_patient_sign',
    'cnsnt_date',
    'patient_hipaa_authorization',
    'consent_pi_solutions_plus',
    'PatientGenderCode',
    'PatientAddress2',
    'PatientCity',
    'PatientState',
    'PatientZipCodeBase',
    'zipcode_5',
    'consent_bi',
    'consent_ni_spevigo',
    'zip_state_code',
    'create_marketing_profile_nevada',
    'share_with_partners',
    'collect_data_marketing',
    'boehringer_email_marketing_communications',
    'create_marketing_profile',
    'hasBeenDiagnosed',
    'salutation',
    'role_position',
    'health_system',
    'email_',
    'phone',
    'therapeutic_area_priority',
    'area_of_quadruple_aim',
    'are_you_a_u_s_licensed_physician',
    'please_choose_an_identification_preference',
    'select_article_to_view',
    'botId',
  ];

  /**
   * Logger methods that trigger WARNING-level messages.
   *
   * These logging methods will generate a warning about potential data exposure
   * AND will inspect arguments for sensitive variables.
   *
   * @var string[]
   */
  private $loggingMethodsWarning = [
    'log',
    'info',
    'notice',
    'warning',
    'error',
    'alert',
    'critical',
    'emergency',
  ];

  /**
   * Logger methods that trigger ERROR-level messages.
   *
   * These logging methods will generate an error about potential data exposure
   * AND will inspect arguments for sensitive variables.
   *
   * @var string[]
   */
  private $loggingMethodsError = [
    'watchdog',
    'debug',
  ];

  /**
   * Returns token types this sniff wants to listen for.
   *
   * @return int[]
   */
  public function register() {
    return [
      T_STRING,                    // Function calls (e.g., watchdog, print_r, logger->info)
      T_VARIABLE,                  // Variable declarations and usage
      T_CONSTANT_ENCAPSED_STRING,  // String literals (for keyword detection, and array keys)
      T_ECHO,                      // Echo statements
      T_PRINT,                     // Print statements
      T_RETURN,                    // Return statements (API responses)
    ];
  }

  /**
   * Processes tokens when encountered.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the current token.
   *
   * @return void
   */
  public function process(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $tokenCode = $tokens[$stackPtr]['code'];

    switch ($tokenCode) {
      case T_STRING:
        $this->processFunctionCall($phpcsFile, $stackPtr);
        break;

      case T_VARIABLE:
        $this->processVariable($phpcsFile, $stackPtr);
        break;

      case T_CONSTANT_ENCAPSED_STRING:
        $this->processStringLiteral($phpcsFile, $stackPtr);
        break;

      case T_ECHO:
      case T_PRINT:
        $this->processDirectOutput($phpcsFile, $stackPtr);
        break;

      case T_RETURN:
        $this->processReturnStatement($phpcsFile, $stackPtr);
        break;
    }
  }

  /**
   * Processes function calls to detect debugging and logging functions.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the function name token.
   *
   * @return void
   */
  private function processFunctionCall(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $functionName = strtolower($tokens[$stackPtr]['content']);

    $isDebugFunc = $this->isDebugFunction($functionName);
    $isLoggerCall = $this->isLoggerServiceCall($phpcsFile, $stackPtr);

    // Check for debugging functions
    if ($isDebugFunc) {
      $phpcsFile->addError(
        sprintf(
          'Use of "%s()" function is meant only for debugging or troubleshooting. Avoid in production.',
          $functionName
        ),
        $stackPtr,
        'DebugFunctionUsage'
      );
      
      // Only inspect arguments if it's NOT also a logger call (to avoid duplicates)
      if (!$isLoggerCall) {
        $this->inspectFunctionArgumentsForSensitiveData(
          $phpcsFile,
          $stackPtr,
          sprintf('Debug function "%s()" may expose sensitive data.', $functionName),
          'SensitiveDebugArgument'
        );
      }
    }

    // Check for logger service calls
    if ($isLoggerCall) {
      $this->inspectLoggerArguments($phpcsFile, $stackPtr, $functionName);
    }
  }

  /**
   * Processes variable tokens to detect sensitive variable usage and hardcoded credentials.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the variable token.
   *
   * @return void
   */
  private function processVariable(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $variableName = $tokens[$stackPtr]['content'];

    // Check if this variable is already being reported in a specific context
    $inReportedContext = $this->isVariableInReportedContext($phpcsFile, $stackPtr);

    $isSensitiveVariableMatch = $this->isSensitiveVariable($variableName);
    $containsSensitiveKeywordPattern = $this->containsSensitiveKeyword($variableName);

    // Report sensitive variable/keyword usage first (if not in a reported context)
    if ($isSensitiveVariableMatch && !$inReportedContext) {
      $phpcsFile->addWarning(
        sprintf(
          'Sensitive variable "%s" detected. Ensure proper handling and avoid logging or exposing this data.',
          $variableName
        ),
        $stackPtr,
        'SensitiveVariableUsage'
      );
    } elseif ($containsSensitiveKeywordPattern && !$inReportedContext) {
      $phpcsFile->addWarning(
        sprintf(
          'Variable "%s" contains sensitive keyword pattern. Ensure proper handling and avoid logging or exposing this data.',
          $variableName
        ),
        $stackPtr,
        'SensitiveKeywordVariableUsage'
      );
    }

    // Check for assignment operator after the variable.
    $next = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);

    if ($next !== false && $tokens[$next]['code'] === T_EQUAL) {
      $valuePtr = $phpcsFile->findNext(T_WHITESPACE, $next + 1, null, true);
      
      if ($valuePtr !== false) {
        if ($this->isHardcodedValue($tokens[$valuePtr])) {
          // If it's a specific sensitive variable/keyword, report as an ERROR (higher severity).
          if ($isSensitiveVariableMatch || $containsSensitiveKeywordPattern) {
            $phpcsFile->addWarning(
              sprintf(
                'Hardcoded credential detected: Sensitive variable "%s" initialized with a literal value. Use environment variables or a secure configuration system.',
                $variableName
              ),
              $valuePtr,
              'HardcodedCredentialSensitiveVariable'
            );
          } else {
            // NEW: Broad check for any variable initialized with a hardcoded value.
            // Use a WARNING level for this broader check.
            $phpcsFile->addWarning(
              sprintf(
                'Variable "%s" is initialized with a hardcoded literal value. Review to ensure it\'s not a credential or sensitive information that should be loaded securely.',
                $variableName
              ),
              $valuePtr,
              'HardcodedLiteralAssignment'
            );
          }
        }
      }
    }
  }

  /**
   * Processes string literals to detect sensitive keywords and hardcoded credentials in array keys.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the string token.
   *
   * @return void
   */
  private function processStringLiteral(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $content = $tokens[$stackPtr]['content'];
    
    // Remove quotes
    $cleanContent = trim($content, '\'"');
    
    // Skip empty strings or very short strings (single characters)
    if (strlen($cleanContent) < 2) {
      return;
    }
    
    // Check if this string is in a context that's already being reported
    if ($this->isStringInReportedContext($phpcsFile, $stackPtr)) {
      return;
    }
    
    $containsSensitiveKeyword = false;
    // Check for sensitive keywords in the string
    foreach ($this->sensitiveKeywords as $keyword) {
      if (stripos($cleanContent, $keyword) !== false) {
        $containsSensitiveKeyword = true;
        $phpcsFile->addWarning(
          sprintf(
            'String literal "%s" contains sensitive keyword "%s". This may indicate sensitive data handling.',
            $cleanContent,
            $keyword
          ),
          $stackPtr,
          'SensitiveKeywordInString'
        );
        // Do not return here, as we might need to check for hardcoded values if it's an array key.
        break; // Only report once per string for keyword detection
      }
    }

    // Check if this string literal is an array key (e.g., `['key'] = 'value'`)
    $prev = $phpcsFile->findPrevious(T_WHITESPACE, $stackPtr - 1, null, true);

    if ($prev !== false && $tokens[$prev]['code'] === T_OPEN_SQUARE_BRACKET) {
      $closeBracket = $phpcsFile->findNext(T_WHITESPACE, $stackPtr + 1, null, true);
      if ($closeBracket !== false && $tokens[$closeBracket]['code'] === T_CLOSE_SQUARE_BRACKET) {
        $assignmentOp = $phpcsFile->findNext(T_WHITESPACE, $closeBracket + 1, null, true);
        
        if ($assignmentOp !== false && $tokens[$assignmentOp]['code'] === T_EQUAL) {
          $valuePtr = $phpcsFile->findNext(T_WHITESPACE, $assignmentOp + 1, null, true);
          
          if ($valuePtr !== false) {
            if ($this->isHardcodedValue($tokens[$valuePtr])) {
              // If the array key contains a sensitive keyword, report as an ERROR.
              if ($containsSensitiveKeyword) {
                $phpcsFile->addWarning(
                  sprintf(
                    'Hardcoded credential detected: Array key "%s" contains a sensitive keyword and is initialized with a literal value. Use environment variables or a secure configuration system.',
                    $cleanContent
                  ),
                  $valuePtr,
                  'HardcodedCredentialSensitiveArrayKey'
                );
              } else {
                // NEW: Broad check for any array key initialized with a hardcoded value.
                // Use a WARNING level for this broader check.
                $phpcsFile->addWarning(
                  sprintf(
                    'Array key "%s" is initialized with a hardcoded literal value. Review to ensure it\'s not a credential or sensitive information that should be loaded securely.',
                    $cleanContent
                  ),
                  $valuePtr,
                  'HardcodedLiteralArrayKey'
                );
              }
            }
          }
        }
      }
    }
  }

  /**
   * Checks if a string literal is within a context that's already being reported.
   *
   * This prevents duplicate warnings for strings in logger, debug, echo, etc.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the string token.
   *
   * @return bool True if in reported context, false otherwise.
   */
  private function isStringInReportedContext(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $line = $tokens[$stackPtr]['line'];
    
    // Look backwards on the same line for function calls or output statements
    for ($i = $stackPtr - 1; $i >= 0 && $tokens[$i]['line'] === $line; $i--) {
      $tokenCode = $tokens[$i]['code'];
      $tokenContent = strtolower($tokens[$i]['content'] ?? '');
      
      // Check if we're inside a logger call
      if ($tokenCode === T_STRING) {
        $allLoggerMethods = array_merge(
          $this->loggingMethodsWarning,
          $this->loggingMethodsError
        );
        
        if (in_array($tokenContent, $allLoggerMethods, true) || $tokenContent === 'watchdog') {
          return true;
        }
        
        // Check if we're inside a debug function
        if ($this->isDebugFunction($tokenContent)) {
          return true;
        }
      }
      
      // Check if we're in echo, print, or return context
      if (in_array($tokenCode, [T_ECHO, T_PRINT, T_RETURN], true)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Checks if a variable is within a context that's already being reported.
   *
   * This prevents duplicate warnings for variables that are already flagged
   * in specific contexts like logger calls, debug functions, etc.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the variable token.
   *
   * @return bool True if the variable is in a reported context, false otherwise.
   */
  private function isVariableInReportedContext(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    
    // Look backwards for function calls, echo, print, or return on the same line
    $line = $tokens[$stackPtr]['line'];
    
    for ($i = $stackPtr - 1; $i >= 0 && $tokens[$i]['line'] === $line; $i--) {
      $tokenCode = $tokens[$i]['code'];
      $tokenContent = strtolower($tokens[$i]['content'] ?? '');
      
      // Check if we're inside a logger call
      if ($tokenCode === T_STRING) {
        $allLoggerMethods = array_merge(
          $this->loggingMethodsWarning,
          $this->loggingMethodsError
        );
        
        if (in_array($tokenContent, $allLoggerMethods, true) || $tokenContent === 'watchdog') {
          return true;
        }
        
        // Check if we're inside a debug function
        if ($this->isDebugFunction($tokenContent)) {
          return true;
        }
      }
      
      // Check if we're in echo, print, or return context
      if (in_array($tokenCode, [T_ECHO, T_PRINT, T_RETURN], true)) {
        return true;
      }
    }
    
    return false;
  }

  /**
   * Processes echo/print statements for sensitive data output.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the echo/print token.
   *
   * @return void
   */
  private function processDirectOutput(File $phpcsFile, int $stackPtr) {
    $this->scanLineForSensitiveData(
      $phpcsFile,
      $stackPtr,
      'Direct output of sensitive data detected.',
      'SensitiveDirectOutput'
    );
  }

  /**
   * Processes return statements for sensitive data in API responses.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the return token.
   *
   * @return void
   */
  private function processReturnStatement(File $phpcsFile, int $stackPtr) {
    $this->scanLineForSensitiveData(
      $phpcsFile,
      $stackPtr,
      'Return statement may expose sensitive data in API response.',
      'SensitiveApiReturn'
    );
  }

  /**
   * Checks if a function name is in the debug functions list.
   *
   * @param string $functionName The function name (lowercase).
   *
   * @return bool
   */
  private function isDebugFunction($functionName) {
    return in_array($functionName, $this->debugFunctions, true);
  }

  /**
   * Determines if the current token is part of a logger service call.
   *
   * Recognizes the following patterns:
   * - watchdog()
   * - \Drupal::logger()->method()
   * - Drupal::logger()->method()
   * - $this->logger->method()
   * - $logger->method()
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the current token.
   *
   * @return bool
   */
  private function isLoggerServiceCall(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    $currentToken = strtolower($tokens[$stackPtr]['content']);

    // Pattern 1: Direct watchdog() call
    if ($currentToken === 'watchdog') {
      return true;
    }

    // Pattern 2: \Drupal::logger() or Drupal::logger()
    if ($currentToken === 'logger') {
      return $this->isDrupalLoggerStaticCall($phpcsFile, $stackPtr);
    }

    // Pattern 3: $logger->method() or $this->logger->method()
    $allLoggerMethods = array_merge(
      $this->loggingMethodsWarning,
      $this->loggingMethodsError
    );

    if (in_array($currentToken, $allLoggerMethods, true)) {
      return $this->isLoggerObjectMethod($phpcsFile, $stackPtr);
    }

    return false;
  }

  /**
   * Checks if the current 'logger' token is part of a Drupal::logger() static call.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the 'logger' token.
   *
   * @return bool
   */
  private function isDrupalLoggerStaticCall(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    
    $doubleColonPtr = $phpcsFile->findPrevious(
      T_DOUBLE_COLON,
      $stackPtr - 1,
      null,
      false,
      null,
      true
    );

    if (!$doubleColonPtr) {
      return false;
    }

    $drupalPtr = $phpcsFile->findPrevious(
      T_STRING,
      $doubleColonPtr - 1,
      null,
      false,
      null,
      true
    );

    return $drupalPtr && strtolower($tokens[$drupalPtr]['content']) === 'drupal';
  }

  /**
   * Checks if the current method is called on a logger object.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $stackPtr  The position of the method name token.
   *
   * @return bool
   */
  private function isLoggerObjectMethod(File $phpcsFile, int $stackPtr) {
    $tokens = $phpcsFile->getTokens();
    
    $objectOpPtr = $phpcsFile->findPrevious(
      T_OBJECT_OPERATOR,
      $stackPtr - 1,
      null,
      false,
      null,
      true
    );

    if (!$objectOpPtr) {
      return false;
    }

    $identifierPtr = $phpcsFile->findPrevious(
      [T_STRING, T_VARIABLE],
      $objectOpPtr - 1,
      null,
      false,
      null,
      true
    );

    if (!$identifierPtr) {
      return false;
    }

    $identifier = strtolower($tokens[$identifierPtr]['content']);
    $loggerIdentifiers = ['logger', '$this', '$logger', '$log'];

    return in_array($identifier, $loggerIdentifiers, true);
  }

  /**
   * Inspects logger function arguments for sensitive data.
   *
   * @param File   $phpcsFile    The file being scanned.
   * @param int    $stackPtr     The position of the logger function name.
   * @param string $functionName The logger function name.
   *
   * @return void
   */
  private function inspectLoggerArguments(File $phpcsFile, int $stackPtr, $functionName) {
    $tokens = $phpcsFile->getTokens();
    
    $openParen = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr);
    if (!$openParen || !isset($tokens[$openParen]['parenthesis_closer'])) {
      return;
    }

    $closeParen = $tokens[$openParen]['parenthesis_closer'];

    // Determine severity level
    $isErrorLevel = in_array($functionName, $this->loggingMethodsError, true);
    $isWarningLevel = in_array($functionName, $this->loggingMethodsWarning, true);

    // Add appropriate message based on severity
    if ($isErrorLevel) {
      $phpcsFile->addError(
        sprintf(
          'Use of "%s()" function / Drupal Logger service log type may expose sensitive information.',
          $functionName
        ),
        $stackPtr,
        'SensitiveLoggerLevelError'
      );
    } elseif ($isWarningLevel) {
      $phpcsFile->addWarning(
        sprintf(
          'Use of "%s()" function / Drupal Logger service log type may expose sensitive information.',
          $functionName
        ),
        $stackPtr,
        'SensitiveLoggerLevelWarning'
      );
    }

    // Check arguments for sensitive variables in ALL logger methods
    if ($isErrorLevel || $isWarningLevel) {
      $this->checkArgumentsForSensitiveVariables(
        $phpcsFile,
        $openParen,
        $closeParen
      );
    }
  }

  /**
   * Checks function arguments for sensitive variables including nested arrays.
   *
   * @param File $phpcsFile The file being scanned.
   * @param int  $start     The opening parenthesis position.
   * @param int  $end       The closing parenthesis position.
   *
   * @return void
   */
  private function checkArgumentsForSensitiveVariables(File $phpcsFile, $start, $end) {
    $tokens = $phpcsFile->getTokens();

    for ($i = $start + 1; $i < $end; $i++) {
      $token = $tokens[$i];
      
      // Check variables at any nesting level
      if ($token['code'] === T_VARIABLE) {
        $variableName = $token['content'];
        
        // Check for exact match first
        if ($this->isSensitiveVariable($variableName)) {
          $phpcsFile->addWarning(
            sprintf(
              'Logger argument may contain sensitive data. Sensitive variable: "%s"',
              $variableName
            ),
            $i,
            'SensitiveLoggerArgumentVariable'
          );
        }
        // Also check for keyword patterns
        elseif ($this->containsSensitiveKeyword($variableName)) {
          $phpcsFile->addWarning(
            sprintf(
              'Logger argument may contain sensitive data. Variable with sensitive keyword: "%s"',
              $variableName
            ),
            $i,
            'SensitiveLoggerArgumentKeyword'
          );
        }
      }
    }
  }

  /**
   * Inspects function arguments for sensitive data (variables, strings, and keywords).
   *
   * @param File   $phpcsFile   The file being scanned.
   * @param int    $stackPtr    The position of the function name.
   * @param string $baseMessage The base warning message.
   * @param string $errorCode   The error code prefix.
   *
   * @return void
   */
  private function inspectFunctionArgumentsForSensitiveData(
    File $phpcsFile,
    $stackPtr,
    $baseMessage,
    $errorCode
  ) {
    $tokens = $phpcsFile->getTokens();
    
    $openParen = $phpcsFile->findNext(T_OPEN_PARENTHESIS, $stackPtr);
    if (!$openParen || !isset($tokens[$openParen]['parenthesis_closer'])) {
      return;
    }

    $closeParen = $tokens[$openParen]['parenthesis_closer'];

    // Check all arguments for sensitive data
    for ($i = $openParen + 1; $i < $closeParen; $i++) {
      $tokenCode = $tokens[$i]['code'];
      $content = $tokens[$i]['content'];

      if ($tokenCode === T_VARIABLE) {
        $this->checkVariableForSensitiveData(
          $phpcsFile,
          $i,
          $content,
          $baseMessage,
          $errorCode
        );
      } elseif ($tokenCode === T_CONSTANT_ENCAPSED_STRING) {
        $this->checkStringForSensitiveData(
          $phpcsFile,
          $i,
          $content,
          $baseMessage,
          $errorCode
        );
      }
    }
  }

  /**
   * Scans the current line for sensitive data in variables and strings.
   *
   * @param File   $phpcsFile   The file being scanned.
   * @param int    $stackPtr    The starting position.
   * @param string $baseMessage The base warning message.
   * @param string $errorCode   The error code prefix.
   *
   * @return void
   */
  private function scanLineForSensitiveData(
    File $phpcsFile,
    $stackPtr,
    $baseMessage,
    $errorCode
  ) {
    $tokens = $phpcsFile->getTokens();
    $line = $tokens[$stackPtr]['line'];

    // Scan all tokens on the same line
    for ($i = $stackPtr + 1; isset($tokens[$i]) && $tokens[$i]['line'] === $line; $i++) {
      $tokenCode = $tokens[$i]['code'];
      $content = $tokens[$i]['content'];

      if ($tokenCode === T_VARIABLE) {
        $this->checkVariableForSensitiveData(
          $phpcsFile,
          $i,
          $content,
          $baseMessage,
          $errorCode
        );
      } elseif ($tokenCode === T_CONSTANT_ENCAPSED_STRING) {
        $this->checkStringForSensitiveData(
          $phpcsFile,
          $i,
          $content,
          $baseMessage,
          $errorCode
        );
      }
    }
  }

  /**
   * Checks if a variable contains sensitive data.
   *
   * @param File   $phpcsFile   The file being scanned.
   * @param int    $stackPtr    The variable token position.
   * @param string $content     The variable name (with $).
   * @param string $baseMessage The base warning message.
   * @param string $errorCode   The error code prefix.
   *
   * @return void
   */
  private function checkVariableForSensitiveData(
    File $phpcsFile,
    $stackPtr,
    $content,
    $baseMessage,
    $errorCode
  ) {
    // Check for exact sensitive variable match
    if ($this->isSensitiveVariable($content)) {
      $phpcsFile->addWarning(
        sprintf('%s Sensitive variable: "%s"', $baseMessage, $content),
        $stackPtr,
        $errorCode . 'Variable'
      );
      return;
    }

    // Check for sensitive keyword pattern
    if ($this->containsSensitiveKeyword($content)) {
      $phpcsFile->addWarning(
        sprintf('%s Variable with sensitive keyword: "%s"', $baseMessage, $content),
        $stackPtr,
        $errorCode . 'KeywordVariable'
      );
    }
  }

  /**
   * Checks if a string literal contains sensitive data references or keywords.
   *
   * @param File   $phpcsFile   The file being scanned.
   * @param int    $stackPtr    The string token position.
   * @param string $content     The string content (with quotes).
   * @param string $baseMessage The base warning message.
   * @param string $errorCode   The error code prefix.
   *
   * @return void
   */
  private function checkStringForSensitiveData(
    File $phpcsFile,
    $stackPtr,
    $content,
    $baseMessage,
    $errorCode
  ) {
    $cleanContent = trim($content, '\'"');

    // Check for sensitive variable name references in strings
    foreach ($this->sensitiveVariables as $var) {
      $varName = trim($var, '$');
      if (stripos($cleanContent, $varName) !== false) {
        $phpcsFile->addWarning(
          sprintf(
            '%s Sensitive variable reference in string: "%s"',
            $baseMessage,
            $cleanContent
          ),
          $stackPtr,
          $errorCode . 'VariableInString'
        );
        return;
      }
    }

    // Check for sensitive keywords in strings
    foreach ($this->sensitiveKeywords as $keyword) {
      if (stripos($cleanContent, $keyword) !== false) {
        $phpcsFile->addWarning(
          sprintf('%s Sensitive keyword: "%s"', $baseMessage, $cleanContent),
          $stackPtr,
          $errorCode . 'Keyword'
        );
        return;
      }
    }
  }

  /**
   * Checks if a variable name is in the sensitive variables list.
   *
   * @param string $variableName The variable name (with $).
   *
   * @return bool
   */
  private function isSensitiveVariable($variableName) {
    return in_array($variableName, $this->sensitiveVariables, true);
  }

  /**
   * Checks if a variable name contains any sensitive keyword patterns.
   *
   * This method checks if the variable name contains any of the sensitive keywords
   * defined in $sensitiveKeywords, allowing detection of variables like:
   * - $password, $user_password, $old_password
   * - $token, $auth_token, $api_token
   * - $secret, $client_secret
   * - $apikey, $api_key
   *
   * @param string $variableName The variable name (with $).
   *
   * @return bool True if the variable contains a sensitive keyword, false otherwise.
   */
  private function containsSensitiveKeyword($variableName) {
    // Remove the $ prefix for checking
    $cleanName = strtolower(ltrim($variableName, '$'));

    foreach ($this->sensitiveKeywords as $keyword) {
      // Check if the keyword appears anywhere in the variable name
      if (strpos($cleanName, strtolower($keyword)) !== false) {
        return true;
      }
    }

    return false;
  }

  /**
   * Checks if a token represents a hardcoded literal value.
   *
   * This includes strings, numbers, booleans (true/false), and null.
   *
   * @param array $token The token array.
   *
   * @return bool
   */
  private function isHardcodedValue(array $token) {
    return in_array(
      $token['code'],
      [
        T_CONSTANT_ENCAPSED_STRING, // 'string', "string"
        T_LNUMBER,                  // 123
        T_DNUMBER,                  // 1.23
        T_TRUE,                     // true
        T_FALSE,                    // false
        T_NULL,                     // null
      ],
      true
    );
  }
}
