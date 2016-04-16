<?php

namespace Mindgruve\TwoFactorAuth;

use Base32\Base32;

class Authenticator
{
    /**
     * @var int
     */
    protected $t0;

    /**
     * @var int
     */
    protected $interval;

    /**
     * @var string
     */
    protected $algo;

    /**
     * @var int
     */
    protected $tokenLength;

    /**
     * $t0 is the Epoch
     * $interval is the interval (ex 30 seconds)
     * $algo is the cryptographic hash algorithm
     * $tokenLength is the number of digits for the token
     *
     * @param int $t0
     * @param int $interval
     * @param string $algo
     * @param int $tokenLength
     */
    public function __construct($t0 = 0, $interval = 30, $algo = 'SHA1', $tokenLength = 6)
    {
        $this->t0 = 0;
        $this->interval = $interval;
        $this->algo = $algo;
        $this->tokenLength = $tokenLength;
    }


    /**
     * Generate a secret
     *
     * @param int $length
     * @return string
     * @throws RFCException
     */
    public function createSecret($length = 20)
    {
        if ($length < 16) {
            throw new RFCException('The secret should be at least 16 characters long (128 bits) .');
        }
        $rand = openssl_random_pseudo_bytes($length);

        return Base32::encode($rand);
    }

    /**
     * Generate a token
     *
     * @param $base32EncodedSecret
     * @param null $time
     * @param int $timeStepOffset
     * @return string
     */
    public function generateToken($base32EncodedSecret, $time = null, $timeStepOffset = 0)
    {
        $secret = Base32::decode($base32EncodedSecret);
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $this->getTimeStep($time) + $timeStepOffset);
        $hm = hash_hmac($this->algo, $time, $secret, true);
        $offset = ord(substr($hm, -1)) & 0x0F;
        $hashpart = substr($hm, $offset, 4);
        $value = unpack('N', $hashpart);
        $value = $value[1];
        $value = $value & 0x7FFFFFFF;
        $modulo = pow(10, $this->tokenLength);

        return str_pad($value % $modulo, $this->tokenLength, '0', STR_PAD_LEFT);
    }

    /**
     * Verify a token
     *
     * @param $base32EncodedSecret
     * @param $token
     * @param null $time
     * @param int $delta
     * @return bool
     */
    public function verifyToken($base32EncodedSecret, $token, $delta = 1, $time = null)
    {
        for ($i = -$delta; $i <= $delta; $i++) {
            $calculatedCode = $this->generateToken($base32EncodedSecret, $time, $i);
            if ($calculatedCode == $token) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the current time step
     *
     * @param null $time
     * @return float
     */
    public function getTimeStep($time = null)
    {
        if (is_null($time)) {
            $time = time();
        }

        return floor(($time - $this->t0) / $this->interval);
    }

    public function getGoogleQRCodeUrl($name, $base32EncodedSecret, $title = null, $height = 200, $width = 200)
    {
        $urlencoded = urlencode('otpauth://totp/' . $name . '?secret=' . $base32EncodedSecret . '');
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer=' . urlencode($title));
        }

        return 'https://chart.googleapis.com/chart?chs=200x200&chld=M|0&cht=qr&chl=' . $urlencoded . '';
    }
}