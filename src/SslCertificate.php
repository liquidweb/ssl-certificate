<?php

namespace LiquidWeb\SslCertificate;

use Carbon\Carbon;
use phpseclib\Math\BigInteger;

class SslCertificate
{
    /** @var bool */
    protected $trusted;

    /** @var bool */
    protected $revoked;

    /** @var string */
    protected $ip;

    /** @var BigInteger */
    protected $serial;

    /** @var string */
    protected $inputDomain;

    /** @var string */
    protected $testedDomain;

    /** @var array */
    protected $certificateFields = [];

    /** @var array */
    protected $certificateChains = [];

    /** @var array */
    protected $connectionMeta = [];

    /** @var SslRevocationList */
    protected $crl;

    /** @var array */
    protected $crlLinks = [];

    /** @var Carbon */
    protected $revokedTime;

    public static function createForHostName(string $url, int $timeout = 30): SslCertificate
    {
        $downloadResults = Downloader::downloadCertificateFromUrl($url, $timeout);

        return new static($downloadResults);
    }

    private static function extractCrlLinks($rawCrlPoints): string
    {
        $tempCrlItem = explode('URI:', $rawCrlPoints);
        $cleanCrlItem = trim($tempCrlItem[1]);

        return $cleanCrlItem;
    }

    private static function parseCrlLinks($rawCrlInput): array
    {
        $crlLinks = [];
        $crlRawItems = explode('Full Name:', $rawCrlInput);
        // Remove the stuff before the first 'Full Name:' item
        array_splice($crlRawItems, 0, 1);
        foreach ($crlRawItems as $item) {
            $crlLink = self::extractCrlLinks($item);
            array_push($crlLinks, $crlLink);
            unset($crlLink);
        }

        return $crlLinks;
    }

    private function getRevokedDate()
    {
        foreach ($this->crl->getRevokedList() as $broke) {
            if ($this->serial->equals($broke['userCertificate'])) {
                return new Carbon($broke['revocationDate']['utcTime']);
            }
        }
    }

    private function isClrRevoked()
    {
        if (! $this->hasCrlLink()) {
            return;
        }
        foreach ($this->crl->getRevokedList() as $broke) {
            if ($this->serial->equals($broke['userCertificate'])) {
                $this->trusted = false;

                return true;
            }
        }

        return false;
    }

    private static function parseCertChains(array $chains): array
    {
        $output = [];
        foreach ($chains as $cert) {
            array_push($output, new SslChain($cert));
        }

        return $output;
    }

    public function __construct(array $downloadResults)
    {
        $this->inputDomain = $downloadResults['inputDomain'];
        $this->testedDomain = $downloadResults['tested'];
        $this->trusted = $downloadResults['trusted'];
        $this->ip = $downloadResults['dns-resolves-to'];
        $this->certificateFields = $downloadResults['cert'];
        $this->certificateChains = self::parseCertChains($downloadResults['full_chain']);
        $this->connectionMeta = $downloadResults['connection'];
        $this->serial = new BigInteger($downloadResults['cert']['serialNumber']);

        if (isset($downloadResults['cert']['extensions']['crlDistributionPoints'])) {
            $this->crlLinks = self::parseCrlLinks($downloadResults['cert']['extensions']['crlDistributionPoints']);
            $this->crl = SslRevocationList::createFromUrl($this->getCrlLinks()[0]);
            $this->revoked = $this->isClrRevoked();
            $this->revokedTime = $this->getRevokedDate();
        }
    }

    public function hasSslChain(): bool
    {
        if (isset($this->certificateChains) && count($this->certificateChains) >= 1) {
            return true;
        }

        return false;
    }

    public function getCertificateFields(): array
    {
        return $this->certificateFields;
    }

    public function getCertificateChains(): array
    {
        return $this->certificateChains;
    }

    public function getSerialNumber(): string
    {
        return strtoupper($this->serial->toHex());
    }

    public function hasCrlLink(): bool
    {
        return isset($this->certificateFields['extensions']['crlDistributionPoints']);
    }

    public function getCrlLinks()
    {
        if (! $this->hasCrlLink()) {
            return;
        }

        return $this->crlLinks;
    }

    public function getCrl()
    {
        if (! $this->hasCrlLink()) {
            return;
        }

        return $this->crl;
    }

    public function isRevoked()
    {
        return $this->revoked;
    }

    public function getCrlRevokedTime()
    {
        if ($this->isRevoked()) {
            return $this->revokedTime;
        }
    }

    public function getResolvedIp(): string
    {
        return $this->ip;
    }

    public function getIssuer(): string
    {
        return $this->certificateFields['issuer']['CN'];
    }

    public function getDomain(): string
    {
        $certDomain = $this->getCertificateDomain();
        if (str_contains($certDomain, $this->inputDomain) === false) {
            return $this->inputDomain;
        }

        return $certDomain ?? '';
    }

    public function getTestedDomain(): string
    {
        return $this->testedDomain;
    }

    public function getInputDomain(): string
    {
        return $this->inputDomain;
    }

    public function getCertificateDomain(): string
    {
        return $this->certificateFields['subject']['CN'];
    }

    public function getAdditionalDomains(): array
    {
        $additionalDomains = explode(', ', $this->certificateFields['extensions']['subjectAltName'] ?? '');

        return array_map(function (string $domain) {
            return str_replace('DNS:', '', $domain);
        }, $additionalDomains);
    }

    public function getSignatureAlgorithm(): string
    {
        return $this->certificateFields['signatureTypeSN'] ?? '';
    }

    public function getConnectionMeta(): array
    {
        return $this->connectionMeta;
    }

    public function validFromDate(): Carbon
    {
        return Carbon::createFromTimestampUTC($this->certificateFields['validFrom_time_t']);
    }

    public function expirationDate(): Carbon
    {
        return Carbon::createFromTimestampUTC($this->certificateFields['validTo_time_t']);
    }

    public function isExpired(): bool
    {
        return $this->expirationDate()->isPast();
    }

    public function isTrusted(): bool
    {
        return $this->trusted;
    }

    public function isValid(string $url = null): bool
    {
        // Verify SSL not expired
        if (! Carbon::now()->between($this->validFromDate(), $this->expirationDate())) {
            return false;
        }
        // Verify the SSL applies to the domain; use $url if provided, other wise use input
        if ($this->appliesToUrl($url ?? $this->inputDomain) === false) {
            return false;
        }
        // Check SerialNumber for CRL list
        if ($this->isRevoked()) {
            return false;
        }

        return true;
    }

    public function isValidUntil(Carbon $carbon, string $url = null): bool
    {
        if ($this->isValidDate($carbon) === false) {
            return false;
        }

        return $this->isValid($url);
    }

    public function isValidDate(Carbon $carbon): bool
    {
        if ($carbon->between($this->validFromDate(), $this->expirationDate()) === false) {
            return false;
        }

        return true;
    }

    public function isSelfSigned()
    {
        // Get the issuer data
        $url = $this->getIssuer();
      // make sure we don't include wildcard if it's there...
        if (starts_with($url, '*.') === true) {
            $url = substr($url, 2);
        }
      //Try to parse the string
        try {
            $issuerUrl = new Url($url);
        } catch (\Exception $e) {
            // if we hit this exception then the string is not likely a URL
            return false;
        }
      // If it is a domain, run appliesToUrl($this->getIssuer())
        if ($this->appliesToUrl($url) === true) {
            return true;
        }

      // default to return null; this means maybe
    }

    public function appliesToUrl(string $url): bool
    {
        if (starts_with($url, '*.') === true) {
            $url = substr($url, 2);
        }
        $host = (new Url($url))->getHostName();

        $certificateHosts = array_merge([$this->getCertificateDomain()], $this->getAdditionalDomains());

        foreach ($certificateHosts as $certificateHost) {
            if ($host === $certificateHost) {
                return true;
            }

            if ($this->wildcardHostCoversHost($certificateHost, $host)) {
                return true;
            }
        }

        return false;
    }

    protected function wildcardHostCoversHost(string $wildcardHost, string $host): bool
    {
        if (! starts_with($wildcardHost, '*')) {
            return false;
        }

        $wildcardHostWithoutWildcard = substr($wildcardHost, 2);

        return ends_with($host, $wildcardHostWithoutWildcard);
    }
}
