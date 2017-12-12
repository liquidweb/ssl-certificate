<?php

namespace LiquidWeb\SslCertificate;

use League\Uri\Parser as UriParser;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;

class Url
{
    /** @var string */
    protected $inputUrl;

    /** @var array */
    protected $parsedUrl;

    /** @var string */
    protected $validatedURL;

    /** @var string */
    protected $ipAddress;

    public function __toString()
    {
        return $this->getInputUrl();
    }

    private static function verifyAndGetDNS($domain): ?string
    {
        $domainIp = gethostbyname($domain);
        if (! filter_var($domainIp, FILTER_VALIDATE_IP)) {
            return null;
        }

        return $domainIp;
    }

    public function __construct(string $url)
    {
        $this->inputUrl = $url;
        $parser = new UriParser();
        $this->parsedUrl = $parser($this->inputUrl);

        // Verify parsing has a host
        if (is_null($this->parsedUrl['host'])) {
            try {
                $this->parsedUrl = $parser('https://'.$this->inputUrl);
            } catch (\Exception $e) {
                throw InvalidUrl::couldNotValidate($url);
            }
            if (is_null($this->parsedUrl['host'])) {
                throw InvalidUrl::couldNotDetermineHost($url);
            }
        }

        if (! filter_var($this->getValidUrl(), FILTER_VALIDATE_URL)) {
            throw InvalidUrl::couldNotValidate($url);
        }

        $this->ipAddress = self::verifyAndGetDNS($this->parsedUrl['host']);
        $this->validatedURL = $url;
    }

    public function getIp(): ?string
    {
        if (null === $this->ipAddress) {
            throw InvalidUrl::couldNotResolveDns($this->inputUrl);
        }

        return $this->ipAddress;
    }

    public function getInputUrl(): string
    {
        return $this->inputUrl;
    }

    public function getHostName(): string
    {
        return $this->parsedUrl['host'];
    }

    public function getValidatedURL(): string
    {
        return $this->validatedURL;
    }

    public function getPort(): string
    {
        return (isset($this->parsedUrl['port'])) ? $this->parsedUrl['port'] : '443';
    }

    public function getTestURL(): string
    {
        return "{$this->getHostName()}:{$this->getPort()}";
    }

    public function getValidUrl(): string
    {
        if ($this->getPort() === '80') {
            return 'http://'.$this->getHostName().'/';
        }

        return 'https://'.$this->getHostName().'/';
    }
}
