<?php

namespace Mindgruve\TwoFactorAuth;

class Authenticator
{
    const DEFAULT_INTERVAL = 30;
    const DEFAULT_TOKEN_LENGTH = 6;
    const DEFAULT_DELTA = 1;

    /**
     * Generate a one time use token
     *
     * @param Secret $secret
     * @param int $interval
     * @param int $tokenLength
     * @param null $timestamp
     * @param int $timeStepOffset
     * @return Token
     */
    public function generateToken(
        Secret $secret,
        $interval = self::DEFAULT_INTERVAL,
        $tokenLength = self::DEFAULT_TOKEN_LENGTH,
        $timestamp = null,
        $timeStepOffset = 0
    ) {
        /**
         * Calculate Timestamp
         */
        $timestamp = !is_null($timestamp) ? $timestamp : time();

        /**
         * Calculate TimeStep
         */
        $timeStep = floor(($timestamp) / $interval);

        /**
         * Generate Binary Time String
         */
        $binaryTimeString = chr(0).chr(0).chr(0).chr(0).pack('N*', $timeStep + $timeStepOffset);

        /**
         * Generate HOTP - https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm
         */
        $hash   = hash_hmac('SHA1', $binaryTimeString, $secret->asBinary(), true);
        $offset = ord(substr($hash, -1)) & 0x0F;
        $sub    = substr($hash, $offset, 4);
        $value  = unpack('N', $sub);
        $value  = $value[1];
        $value  = $value & 0x7FFFFFFF;
        $modulo = pow(10, $tokenLength);
        $token  = str_pad($value % $modulo, $tokenLength, '0', STR_PAD_LEFT);

        return new Token($token);
    }

    /**
     * Verify that a one time use token is valid
     *
     * Token will be valid if within this interval: time() ± delta * interval
     *
     * @param Secret $secret
     * @param $token
     * @param int $delta
     * @param int $interval
     * @param int $tokenLength
     * @param null $timestamp
     * @return bool
     */
    public function verifyToken(
        Secret $secret,
        Token $token,
        $delta = self::DEFAULT_DELTA,
        $interval = self::DEFAULT_INTERVAL,
        $tokenLength = self::DEFAULT_TOKEN_LENGTH,
        $timestamp = null
    ) {
        /**
         * Check Deltas
         */
        if ($delta == 0) {
            /**
             * Check only for this time step
             */
            $generatedToken = $this->generateToken($secret, $interval, $tokenLength, $timestamp, 0);
            if ($generatedToken->getValue() == $token->getValue()
            ) {
                return true;
            }

        } else {
            /**
             * Check each of the deltas
             */
            for ($i = -$delta; $i <= $delta; $i++) {
                $generatedToken = $this->generateToken($secret, $interval, $tokenLength, $timestamp, $i);
                if ($generatedToken->getValue() == $token->getValue()) {
                    return true;
                }
            }
        }

        return false;
    }
}