<?php

namespace Mindgruve\TwoFactorAuth;

use PHPUnit_Framework_TestCase;

class TokenTest extends PHPUnit_Framework_TestCase
{
    public function testConstructor()
    {
        $sut = new Token('ABC123');
        $this->assertEquals('ABC123', $sut->getValue());
        $this->assertEquals('ABC123', $sut->__toString());
    }
}