<?php

namespace Mindgruve\TwoFactorAuth;

use PHPUnit_Framework_TestCase;

class AuthenticatorTest extends PHPUnit_Framework_TestCase
{
    const SECRET = 'QIX5O3XMEYA23WZBV7L7MGV62ME4VVHL';

    public function testGenerateToken()
    {
        $secret = new Secret(self::SECRET);
        $sut    = new Authenticator();

        /**
         * Case #1
         */
        $token = $sut->generateToken(
            $secret,
            Authenticator::DEFAULT_INTERVAL,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            0,
            0
        );

        $this->assertEquals('418898', $token->getValue());
        $this->assertTrue($token instanceof Token);

        /**
         * Case #2
         */
        $token = $sut->generateToken(
            $secret,
            Authenticator::DEFAULT_INTERVAL,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            0,
            1
        );

        $this->assertEquals('233463', $token->getValue());

        /**
         * Case #3
         */
        $token = $sut->generateToken(
            $secret,
            Authenticator::DEFAULT_INTERVAL,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            29,
            0
        );

        $this->assertEquals('418898', $token->getValue());

        /**
         * Case #4
         */
        $token = $sut->generateToken(
            $secret,
            15,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            0,
            2
        );

        $this->assertEquals('515487', $token->getValue());

        /**
         * Case #5
         */
        $token = $sut->generateToken(
            $secret,
            15,
            5,
            0,
            2
        );

        $this->assertEquals('15487', $token->getValue());
    }

    public function testVerifyToken()
    {
        $secret = new Secret(self::SECRET);
        $sut    = new Authenticator();

        /**
         * Case #1
         */
        $token = $sut->generateToken(
            $secret,
            Authenticator::DEFAULT_INTERVAL,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            0,
            0
        );

        $this->assertTrue(
            $sut->isValidToken(
                $secret,
                $token,
                Authenticator::DEFAULT_DELTA,
                Authenticator::DEFAULT_INTERVAL,
                Authenticator::DEFAULT_TOKEN_LENGTH,
                0
            )
        );

        /**
         * Case #2
         */
        $token = $sut->generateToken(
            $secret,
            Authenticator::DEFAULT_INTERVAL,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            40,
            0
        );

        $this->assertTrue(
            $sut->isValidToken(
                $secret,
                $token,
                Authenticator::DEFAULT_DELTA,
                Authenticator::DEFAULT_INTERVAL,
                Authenticator::DEFAULT_TOKEN_LENGTH,
                40
            )
        );

        /**
         * Case #3
         */
        $token = $sut->generateToken(
            $secret,
            Authenticator::DEFAULT_INTERVAL,
            Authenticator::DEFAULT_TOKEN_LENGTH,
            10,
            1
        );

        $this->assertTrue(
            $sut->isValidToken(
                $secret,
                $token,
                Authenticator::DEFAULT_DELTA,
                Authenticator::DEFAULT_INTERVAL,
                Authenticator::DEFAULT_TOKEN_LENGTH,
                40
            )
        );
    }

}