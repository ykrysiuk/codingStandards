<?php

namespace PtpStandard\Snffs\Classes;

use PHP_CodeSniffer\Files\File;
use PHP_CodeSniffer\Sniffs\Sniff;
use PHP_CodeSniffer\Util\Tokens;

class DisallowMagicCallsSniff implements Sniff {

  public function register() {
    return [T_OBJECT_OPERATOR];
  }

  public function process(File $phpcsFile, $stackPtr) {
    $tokens = $phpcsFile->getTokens();

    // Ensure we're dealing with the '->' operator
    if ($tokens[$stackPtr]['code'] !== T_OBJECT_OPERATOR) {
      return;
    }

    $nextToken = $phpcsFile->findNext(Tokens::$emptyTokens, ($stackPtr + 1), null, true);

    // If the next token is a string, check for magic methods
    if ($nextToken && $tokens[$nextToken]['code'] === T_STRING) {
      $methodName = $tokens[$nextToken]['content'];

      // Detect magic calls and add errors
      if ($this->isMagicCall($phpcsFile, $tokens, $nextToken, $methodName)) {
        $error = 'Magic call detected. Use $node->get("field_some_name")->getValue() instead.';
        $phpcsFile->addError($error, $stackPtr, 'MagicCallDetected');
      }
    }
  }

  /**
   * Check for magic calls based on method name.
   *
   * @param File $phpcsFile
   * @param array $tokens
   * @param int $nextToken
   * @param string $methodName
   * @return bool
   */
  private function isMagicCall(File $phpcsFile, array $tokens, int $nextToken, string $methodName): bool {
    return match ($methodName) {
      'get' => $this->checkChainedCall($phpcsFile, $tokens, $nextToken, 'value'),
      'value', 'getValue' => $this->checkPreviousObjectOperator($phpcsFile, $tokens, $nextToken),
      'first' => $this->checkChainedCall($phpcsFile, $tokens, $nextToken, 'value'),
      default => false,
    };
  }

  /**
   * Check for chained method calls like $node->get('field_name')->value
   *
   * @param File $phpcsFile
   * @param array $tokens
   * @param int $methodToken
   * @param string $expectedMethod
   * @return bool
   */
  private function checkChainedCall(File $phpcsFile, array $tokens, int $methodToken, string $expectedMethod) {
    $closingParenthesis = $phpcsFile->findNext(T_CLOSE_PARENTHESIS, ($methodToken + 1));
    if ($closingParenthesis) {
      $nextOperator = $phpcsFile->findNext(Tokens::$emptyTokens, ($closingParenthesis + 1), null, true);
      if ($nextOperator && $tokens[$nextOperator]['code'] === T_OBJECT_OPERATOR) {
        $valueToken = $phpcsFile->findNext(Tokens::$emptyTokens, ($nextOperator + 1), null, true);
        if ($valueToken && $tokens[$valueToken]['code'] === T_STRING && $tokens[$valueToken]['content'] === $expectedMethod) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Check if the previous token indicates an object property access like $node->field->value
   *
   * @param File $phpcsFile
   * @param array $tokens
   * @param int $methodToken
   * @return bool
   */
  private function checkPreviousObjectOperator(File $phpcsFile, array $tokens, int $methodToken) {
    $prevOperator = $phpcsFile->findPrevious(T_OBJECT_OPERATOR, ($methodToken - 1), null);
    if ($prevOperator) {
      $varToken = $phpcsFile->findPrevious(T_STRING, ($prevOperator - 1), null);
      if ($varToken && $tokens[$varToken]['code'] === T_STRING && $tokens[$varToken]['content'] !== 'this') {
        return true;
      }
    }
    return false;
  }
}
