<?php

namespace LiquidWeb\SslCertificate;

use Carbon\Carbon;

class SslRevocationList
{
    /** @var Carbon */
    protected $timestamp;

    /** @var IssuerMeta */
    protected $issuer;

    /** @var Carbon */
    protected $createdAt;

    /** @var Carbon */
    protected $expiration;

    /** @var int */
    protected $ttl;

    /** @var string */
    protected $signature;

    /** @var array */
    protected $signatureAlgorithm = [];

    /** @var array */
    protected $revokedCertsList = [];

    public static function createFromUrl(string $url): self
    {
        $downloadResults = Downloader::downloadRevocationListFromUrl($url);
        $tbsCertList = $downloadResults['tbsCertList'];
        $issuer = IssuerMeta::fromRdnSequence($tbsCertList['issuer']['rdnSequence']);
        $createdAt = $tbsCertList['thisUpdate']['utcTime'];
        $expiration = $tbsCertList['nextUpdate']['utcTime'];
        $signature = $downloadResults['signature'];
        $signatureAlgorithm = $downloadResults['signatureAlgorithm'];
        $certsList = $tbsCertList['revokedCertificates'];

        return new static($issuer, $createdAt, $expiration, $signature, $signatureAlgorithm, $certsList);
    }

    public function __construct(IssuerMeta $issuer = null, string $createdAt = '', string $expiration = '', string $signature = '', array $signatureAlgorithm = [], array $certsList = [])
    {
        $this->timestamp = Carbon::now();
        $this->issuer = $issuer;
        $this->createdAt = Carbon::parse($createdAt)->setTimezone('UTC');
        $this->expiration = Carbon::parse($expiration)->setTimezone('UTC');
        $this->ttl = Carbon::parse($expiration)->diffInMinutes(Carbon::now());
        $this->signature = $signature;
        $this->signatureAlgorithm = $signatureAlgorithm;
        $this->revokedCertsList = $certsList;
    }

    public function getRevokedList(): array
    {
        return $this->revokedCertsList;
    }
}
