<?php

namespace Mindgruve\TwoFactorAuth;

use Base32\Base32;
use PHPUnit_Framework_TestCase;

class SecretTest extends PHPUnit_Framework_TestCase
{
    const SECRET = 'QIX5O3XMEYA23WZBV7L7MGV62ME4VVHL';

    public function testConstructor()
    {
        /**
         * Default Constructor
         */
        $sut = new Secret();
        $this->assertEquals(32, strlen($sut->asBase32()));

        /**
         * Testing exception
         */
        try {
            new Secret(null, 15);
            $this->fail();
        } catch (\Exception $e) {
            $this->assertEquals('Exception', get_class($e));
        }
    }

    public function testAsBase32()
    {
        $sut = new Secret(self::SECRET);
        $this->assertEquals(self::SECRET, $sut->asBase32());
    }

    public function testAsBinary()
    {
        $sut = new Secret(self::SECRET);
        $this->assertEquals(Base32::decode(self::SECRET), $sut->asBinary());
    }

    public function testToString()
    {
        $sut = new Secret(self::SECRET);
        $this->assertEquals(self::SECRET, $sut->__toString());
    }

    public function testGetGoogleQRCodeUrl()
    {
        $sut = new Secret(self::SECRET);
        $this->assertEquals(
            'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2FTEST%3Fsecret%3DQIX5O3XMEYA23WZBV7L7MGV62ME4VVHL',
            $sut->getGoogleQRCodeUrl('TEST')
        );
    }
}