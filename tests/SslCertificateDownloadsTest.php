<?php

namespace LiquidWeb\SslCertificate\Test;

use \PHPUnit\Framework\TestCase;
use LiquidWeb\SslCertificate\SslCertificate;

class SslCertificateDownloadsTest extends TestCase
{
    /** @test */
    public function it_can_create_an_instance_for_the_given_host()
    {
        $downloadedCertificate = SslCertificate::createForHostName('liquidweb.com')->withSslCrlCheck();

        $this->assertSame('www.liquidweb.com', $downloadedCertificate->getDomain());
        $this->assertSame(true, $downloadedCertificate->isValid());
        $this->assertSame(false, $downloadedCertificate->isRevoked());
    }

    /** @test */
    public function it_can_verify_host_domains()
    {
        $downloadedCertificate = SslCertificate::createForHostName('google.com');

        $this->assertSame('*.google.com', $downloadedCertificate->getDomain());
        $this->assertSame(true, $downloadedCertificate->appliesToUrl('*.google.com'));
    }

    /** @test */
    public function it_can_verify_nasty_ssls()
    {
        $downloadedCertificate = SslCertificate::createForHostName('edellroot.badssl.com');

        $this->assertSame(false, $downloadedCertificate->isSelfSigned());
        $this->assertSame(false, $downloadedCertificate->appliesToUrl('badssl.com'));
        $this->assertSame('edellroot.badssl.com', $downloadedCertificate->getDomain());
    }
}
