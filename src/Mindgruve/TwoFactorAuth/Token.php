<?php

namespace Mindgruve\TwoFactorAuth;

class Token
{

    protected $value;

    /**
     * @param $value
     */
    public function __construct($value)
    {
        $this->value = $value;
    }

    /**
     * @return mixed
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * @return string
     */
    function __toString()
    {
        return $this->getValue();
    }
}