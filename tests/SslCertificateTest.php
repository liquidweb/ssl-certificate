<?php

namespace LiquidWeb\SslCertificate\Test;

use Carbon\Carbon;
use PHPUnit_Framework_TestCase;
use LiquidWeb\SslCertificate\SslCertificate;

class SslCertificateTest extends PHPUnit_Framework_TestCase
{
    /** @var SslCertificate */
    protected $certificate;

    public function setUp()
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::create('2016', '06', '01', '00', '00', '00', 'utc'));

        $rawDownloaderFields = json_decode(file_get_contents(__DIR__.'/stubs/spatieCertificateFields.json'), true);

        $this->certificate = new SslCertificate($rawDownloaderFields);
    }

    /** @test */
    public function it_can_determine_the_issuer()
    {
        $this->assertSame("Let's Encrypt Authority X3", $this->certificate->getIssuer());
    }

    /** @test */
    public function it_can_determine_ssl_serial()
    {
        $this->assertSame('031383978A14D54B9724863B3D758AE66624', $this->certificate->getSerialNumber());
    }

    /** @test */
    public function it_can_determine_domain_ip()
    {
        $this->assertSame('46.101.151.54', $this->certificate->getResolvedIp());
    }

    /** @test */
    public function it_can_determine_valid_status()
    {
        $this->assertSame(true, $this->certificate->isValid());
    }

    /** @test */
    public function it_can_determine_trust_status()
    {
        $this->assertSame(true, $this->certificate->isTrusted());
    }

    /** @test */
    public function it_can_determine_if_has_ssl_chain()
    {
        $this->assertSame(true, $this->certificate->hasSslChain());
    }

    /** @test */
    public function it_can_determine_the_tested_domain()
    {
        $this->assertSame('spatie.be:443', $this->certificate->getTestedDomain());
    }

    /** @test */
    public function it_can_determine_crl_status()
    {
        $this->assertSame(null, $this->certificate->isRevoked());
    }

    /** @test */
    public function it_can_get_the_raw_fields()
    {
        $this->assertInternalType('array', $this->certificate->getCertificateFields());
    }

    /** @test */
    public function it_can_get_the_chains()
    {
        $this->assertInternalType('array', $this->certificate->getCertificateChains());
    }

    /** @test */
    public function it_can_determine_the_domain()
    {
        $this->assertSame('spatie.be', $this->certificate->getDomain());
    }

    /** @test */
    public function it_can_determine_the_signature_algorithm()
    {
        $this->assertSame('RSA-SHA256', $this->certificate->getSignatureAlgorithm());
    }

    /** @test */
    public function it_can_determine_the_additional_domains()
    {
        $this->assertCount(3, $this->certificate->getAdditionalDomains());

        $this->assertSame('spatie.be', $this->certificate->getAdditionalDomains()[0]);
        $this->assertSame('www.spatie.be', $this->certificate->getAdditionalDomains()[1]);
        $this->assertSame('*.otherdomain.com', $this->certificate->getAdditionalDomains()[2]);
    }

    /** @test */
    public function it_can_determine_the_valid_from_date()
    {
        $this->assertInstanceOf(Carbon::class, $this->certificate->validFromDate());

        $this->assertSame('2016-05-19 16:50:00', $this->certificate->validFromDate()->format('Y-m-d H:i:s'));
    }

    /** @test */
    public function it_can_determine_the_expiration_date()
    {
        $this->assertInstanceOf(Carbon::class, $this->certificate->expirationDate());

        $this->assertSame('2016-08-17 16:50:00', $this->certificate->expirationDate()->format('Y-m-d H:i:s'));
    }

    /** @test */
    public function it_can_determine_if_the_certificate_is_valid()
    {
        Carbon::setTestNow(Carbon::create('2016', '05', '19', '16', '45', '00', 'utc'));
        $this->assertFalse($this->certificate->isValid());

        Carbon::setTestNow(Carbon::create('2016', '05', '19', '16', '51', '00', 'utc'));
        $this->assertTrue($this->certificate->isValid());

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '49', '00', 'utc'));
        $this->assertTrue($this->certificate->isValid());

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '51', '00', 'utc'));
        $this->assertFalse($this->certificate->isValid());
    }

    /** @test */
    public function it_can_determine_if_the_certificate_is_expired()
    {
        Carbon::setTestNow(Carbon::create('2016', '05', '19', '16', '45', '00', 'utc'));
        $this->assertFalse($this->certificate->isExpired());

        Carbon::setTestNow(Carbon::create('2016', '05', '19', '16', '51', '00', 'utc'));
        $this->assertFalse($this->certificate->isExpired());

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '49', '00', 'utc'));
        $this->assertFalse($this->certificate->isExpired());

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '51', '00', 'utc'));
        $this->assertTrue($this->certificate->isExpired());
    }

    /** @test */
    public function it_can_determine_if_the_certificate_is_valid_until_a_date()
    {
        // Expire date of certificate is: 17/08/2016 16:50
        Carbon::setTestNow(Carbon::create('2016', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - True
        $this->assertTrue($this->certificate->isValidUntil(Carbon::now()->addDays(2)));     // 12/08    16:49 - True

        Carbon::setTestNow(Carbon::create('2016', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - True
        $this->assertFalse($this->certificate->isValidUntil(Carbon::now()->addDays(8)));      // 18/08  16:49 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '16', '16', '49', '00', 'utc'));     // 16/08   16:49 - True
        $this->assertTrue($this->certificate->isValidUntil(Carbon::now()->addDays(1)));     // 17/08    16:49 - True

        Carbon::setTestNow(Carbon::create('2016', '08', '16', '16', '51', '00', 'utc'));     // 16/08   16:51 - True
        $this->assertFalse($this->certificate->isValidUntil(Carbon::now()->addDays(1)));      // 17/08  16:51 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '49', '00', 'utc'));     // 17/08   16:49 - True
        $this->assertFalse($this->certificate->isValidUntil(Carbon::now()->addDays(1)));      // 18/08  16:49 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '51', '00', 'utc'));     // 17/08   16:51 - False
        $this->assertFalse($this->certificate->isValidUntil(Carbon::now()->addDays(1)));     // 17/08   16:51 - False
    }

    /** @test */
    public function it_can_determine_if_the_certificate_is_valid_date_function()
    {
        // Start date of certificate is: 19/05/2016 16:50
        // Expire date of certificate is: 17/08/2016 16:50
        Carbon::setTestNow(Carbon::create('2016', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - True
        $this->assertTrue($this->certificate->isValidDate(Carbon::now()->addDays(2)));     // 12/08    16:49 - True

        Carbon::setTestNow(Carbon::create('2016', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - True
        $this->assertFalse($this->certificate->isValidDate(Carbon::now()->addDays(8)));      // 18/08  16:49 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '16', '16', '49', '00', 'utc'));     // 16/08   16:49 - True
        $this->assertTrue($this->certificate->isValidDate(Carbon::now()->addDays(1)));     // 17/08    16:49 - True

        Carbon::setTestNow(Carbon::create('2016', '08', '16', '16', '51', '00', 'utc'));     // 16/08   16:51 - True
        $this->assertFalse($this->certificate->isValidDate(Carbon::now()->addDays(1)));      // 17/08  16:51 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '49', '00', 'utc'));     // 17/08   16:49 - True
        $this->assertFalse($this->certificate->isValidDate(Carbon::now()->addDays(1)));      // 18/08  16:49 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '17', '16', '51', '00', 'utc'));     // 17/08   16:51 - False
        $this->assertFalse($this->certificate->isValidDate(Carbon::now()->addDays(1)));     // 17/08   16:51 - False

        Carbon::setTestNow(Carbon::create('2016', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - True
        $this->assertTrue($this->certificate->isValidDate(Carbon::create('2016', '08', '12', '16', '49', '00', 'utc')));

        Carbon::setTestNow(Carbon::create('2018', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - False
        $this->assertTrue($this->certificate->isValidDate(Carbon::create('2016', '08', '12', '16', '49', '00', 'utc')));

        Carbon::setTestNow(Carbon::create('2014', '08', '10', '16', '49', '00', 'utc'));     // 10/08   16:49 - False
        $this->assertTrue($this->certificate->isValidDate(Carbon::create('2016', '08', '12', '16', '49', '00', 'utc')));
    }

    /** @test */
    public function it_can_determine_if_the_certificate_is_valid_for_a_certain_domain()
    {
        $this->assertTrue($this->certificate->isValid('spatie.be'));

        $this->assertTrue($this->certificate->isValid('www.spatie.be'));

        $this->assertTrue($this->certificate->isValid('otherdomain.com'));

        $this->assertTrue($this->certificate->isValid('www.otherdomain.com'));

        $this->assertTrue($this->certificate->isValid('another.otherdomain.com'));

        $this->assertFalse($this->certificate->isValid('facebook.com'));
    }

    /** @test */
    public function it_can_check_a_revoked_ssl()
    {
        $rawRevokedFields = json_decode(file_get_contents(__DIR__.'/stubs/revokedCertificateFields.json'), true);
        $revokedSslCert = (new SslCertificate($rawRevokedFields))->withSslCrlCheck();

        $this->assertSame(true, $revokedSslCert->isRevoked());
        $this->assertSame(false, $revokedSslCert->isValid());
        $this->assertInternalType('object', $revokedSslCert->getCrlRevokedTime());
    }

    /** @test */
    public function it_can_check_a_ssl_missing_chains()
    {
        $rawRevokedFields = json_decode(file_get_contents(__DIR__.'/stubs/incompleteCertificateFields.json'), true);
        $incompleteSslCert = new SslCertificate($rawRevokedFields);

        $this->assertSame(false, $incompleteSslCert->hasSslChain());
    }
}
