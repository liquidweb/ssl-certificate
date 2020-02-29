<?php

namespace LiquidWeb\SslCertificate\Test;

use Carbon\Carbon;
use PHPUnit\Framework\TestCase;
use LiquidWeb\SslCertificate\SslChain;

class SslChainTest extends TestCase
{
    /** @var SslChain */
    protected $chain;

    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::create('2016', '06', '01', '00', '00', '00', 'utc'));

        $rawChainFields = json_decode(file_get_contents(__DIR__.'/stubs/lucidChainFields.json'), true);

        $this->chain = new SslChain($rawChainFields);
    }

    /** @test */
    public function it_can_determine_ssl_serial()
    {
        $this->assertSame('2643BB32A166487AE19D6C79C43FE266', $this->chain->getSerialNumber());
    }

    /** @test */
    public function it_can_determine_ssl_hash()
    {
        $this->assertSame('dd3d8fe2', $this->chain->getHash());
    }

    /** @test */
    public function it_can_determine_common_name()
    {
        $this->assertSame('StartCom Class 2 IV Server CA', $this->chain->getCommonName());
    }

    /** @test */
    public function it_can_determine_location_name()
    {
        $this->assertSame('IL', $this->chain->getLocationName());
    }

    /** @test */
    public function it_can_determine_organization_name()
    {
        $this->assertSame('StartCom Ltd.', $this->chain->getOrganizationName());
    }

    /** @test */
    public function it_can_determine_organization_unitname()
    {
        $this->assertSame('StartCom Certification Authority', $this->chain->getOrganizationUnitName());
    }

    /** @test */
    public function it_can_determine_issuer_common_name()
    {
        $this->assertSame('StartCom Certification Authority', $this->chain->getIssuerCommonName());
    }

    /** @test */
    public function it_can_determine_issuer_location_name()
    {
        $this->assertSame('IL', $this->chain->getIssuerLocationName());
    }

    /** @test */
    public function it_can_determine_issuer_organization_name()
    {
        $this->assertSame('StartCom Ltd.', $this->chain->getIssuerOrganizationName());
    }

    /** @test */
    public function it_can_determine_issuer_organization_unitname()
    {
        $this->assertSame('Secure Digital Certificate Signing', $this->chain->getIssuerOrganizationUnitName());
    }

    /** @test */
    public function it_can_determine_the_valid_from_date()
    {
        $this->assertInstanceOf(Carbon::class, $this->chain->validFromDate());

        $this->assertSame('2015-12-16 01:00:05', $this->chain->validFromDate()->format('Y-m-d H:i:s'));
    }

    /** @test */
    public function it_can_determine_the_expiration_date()
    {
        $this->assertInstanceOf(Carbon::class, $this->chain->expirationDate());

        $this->assertSame('2030-12-16 01:00:05', $this->chain->expirationDate()->format('Y-m-d H:i:s'));
    }

    /** @test */
    public function it_can_determine_the_signature_algorithm()
    {
        $this->assertSame('RSA-SHA256', $this->chain->getSignatureAlgorithm());
    }

    /** @test */
    public function it_can_determine_valid_status()
    {
        $this->assertSame(true, $this->chain->isValid());
    }

    /** @test */
    public function it_can_determine_expired_status()
    {
        $this->assertSame(false, $this->chain->isExpired());
    }

    /** @test */
    public function it_can_determine_valid_status_in_the_future()
    {
        $this->assertSame(false, $this->chain->isValidUntil(Carbon::now()->addDays(2)));
    }

    /** @test */
    public function it_can_determine_thawte_issuer_organization_unitname()
    {
        $rawChainFields = json_decode(file_get_contents(__DIR__.'/stubs/thawteChainFields.json'), true);
        $revokedSslCert = new SslChain($rawChainFields);

        $this->assertSame('Certification Services Division', $revokedSslCert->getIssuerOrganizationUnitName());
    }
}
