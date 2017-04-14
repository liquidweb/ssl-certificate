<?php

namespace LiquidWeb\SslCertificate;

use Carbon\Carbon;
use phpseclib\Math\BigInteger;

class SslChain
{
    /** @var string */
    protected $name;

    /** @var array */
    protected $subject;

    /** @var string */
    protected $hash;

    /** @var array */
    protected $issuer;

    /** @var string */
    protected $version;

    /** @var BigInteger */
    protected $serial;

    /** @var Carbon */
    protected $validFrom;

    /** @var Carbon */
    protected $validTo;

    /** @var string */
    protected $signatureType;

    private static function setValidFromDate($utcInput): Carbon
    {
        return Carbon::createFromTimestampUTC($utcInput);
    }

    private static function setValidToDate($utcInput): Carbon
    {
        return Carbon::createFromTimestampUTC($utcInput);
    }

    public function __construct(array $chainInput)
    {
        $this->name = $chainInput['name'];
        $this->subject = $chainInput['subject'];
        $this->hash = $chainInput['hash'];
        $this->issuer = $chainInput['issuer'];
        $this->version = $chainInput['version'];
        $this->serial = new BigInteger($chainInput['serialNumber']);
        $this->validFrom = self::setValidFromDate($chainInput['validFrom_time_t']);
        $this->validTo = self::setValidToDate($chainInput['validTo_time_t']);
        $this->signatureType = $chainInput['signatureTypeSN'];
    }

    public function getLocationName(): string
    {
        return $this->subject['C'] ?? '';
    }

    public function getOrganizationName(): string
    {
        return $this->subject['O'] ?? '';
    }

    public function getOrganizationUnitName(): string
    {
        return $this->subject['OU'] ?? '';
    }

    public function getCommonName(): string
    {
        return $this->subject['CN'] ?? '';
    }

    public function getHash(): string
    {
        return $this->hash;
    }

    public function getIssuerLocationName(): string
    {
        return $this->issuer['C'] ?? '';
    }

    public function getIssuerOrganizationName(): string
    {
        return $this->issuer['O'] ?? '';
    }

    public function getIssuerOrganizationUnitName(): string
    {
        if (isset($this->issuer['OU']) === true) {
            if (is_array($this->issuer['OU']) === true) {
                return $this->issuer['OU'][0] ?? '';
            }
        }

        return $this->issuer['OU'] ?? '';
    }

    public function getIssuerCommonName(): string
    {
        return $this->issuer['CN'] ?? '';
    }

    public function getSerialNumber(): string
    {
        return strtoupper($this->serial->toHex());
    }

    public function validFromDate(): Carbon
    {
        return $this->validFrom;
    }

    public function expirationDate(): Carbon
    {
        return $this->validTo;
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->signatureType;
    }

    public function isExpired(): bool
    {
        return $this->expirationDate()->isPast();
    }

    public function isValid()
    {
        if (Carbon::now()->between($this->validFromDate(), $this->expirationDate()) === false) {
            return false;
        }

        return true;
    }

    public function isValidUntil(Carbon $carbon): bool
    {
        if ($this->expirationDate()->gt($carbon) === true) {
            return false;
        }

        return $this->isValid();
    }
}
