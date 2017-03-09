<?php

namespace Mindgruve\TwoFactorAuth;

use Base32\Base32;

class Secret
{
    protected $data;

    /**
     * @param null $base32EncodedString
     * @param int $randomBytes
     * @throws \Exception
     */
    public function __construct($base32EncodedString = null, $randomBytes = 20)
    {
        if ($base32EncodedString) {
            /**
             * Use the provided Base32EncodedString
             */
            $this->data = Base32::decode($base32EncodedString);
        } else {
            /**
             * Validate length
             */
            if ($randomBytes < 16) {
                throw new \Exception('The secret should be at least 16 bytes long (128 bits) .');
            }

            /**
             * Generate Random Bits
             */
            $this->data = openssl_random_pseudo_bytes($randomBytes);
        }
    }

    /**
     * Generate URL to QRCode Using Google Chart
     *
     * @param $name
     * @param null $title
     * @param int $height
     * @param int $width
     * @return string
     */
    public function getGoogleQRCodeUrl($name, $title = null, $height = 200, $width = 200)
    {
        $data = 'otpauth://totp/'.$name.'?secret='.$this->asBase32().($title ? '&issuer='.$title : '');

        return 'https://chart.googleapis.com/chart?chs='.$width.'x'.$height.'&chld=M|0&cht=qr&chl='.urlencode($data).'';
    }

    /**
     * Binary Data
     *
     * @return string
     */
    public function asBinary()
    {
        return $this->data;
    }

    /**
     * Base32 String
     *
     * @return string
     */
    public function asBase32()
    {
        return Base32::encode($this->data);
    }

    /**
     * @return string
     */
    function __toString()
    {
        return $this->asBase32();
    }
}