<?php

namespace LiquidWeb\SslCertificate\Test;

use \PHPUnit\Framework\TestCase;
use LiquidWeb\SslCertificate\Downloader;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;
use LiquidWeb\SslCertificate\Exceptions\CouldNotDownloadCertificate;

class DownloaderTest extends TestCase
{
    /** @test */
    public function it_can_download_a_certificate_from_a_host_name()
    {
        $downloadResults = Downloader::downloadCertificateFromUrl('spatie.be', 10);

        $this->assertTrue(is_array($downloadResults));
        $this->assertTrue(is_array($downloadResults['cert']));

        $this->assertSame('/CN=spatie.be', $downloadResults['cert']['name']);
    }

    /** @test */
    public function it_can_track_ssl_trusted_status_correctly()
    {
        $downloadResults = Downloader::downloadCertificateFromUrl('selfsigned.badssl.com', 10);

        $this->assertTrue(is_array($downloadResults));
        $this->assertTrue(is_array($downloadResults['cert']));
        $this->assertFalse($downloadResults['trusted']);

        $this->assertSame('/C=US/ST=California/L=San Francisco/O=BadSSL Fallback. Unknown subdomain or no SNI./CN=badssl-fallback-unknown-subdomain-or-no-sni', $downloadResults['cert']['name']);
    }

    /** @test */
    public function it_can_track_test_domains()
    {
        $downloadResults = Downloader::downloadCertificateFromUrl('spatie.be:443', 10);
        $this->assertTrue(is_array($downloadResults));
        $this->assertSame('spatie.be:443', $downloadResults['inputDomain']);
        $this->assertSame('spatie.be:443', $downloadResults['tested']);
        $downloadResults = null;

        $downloadResults = Downloader::downloadCertificateFromUrl('http://spatie.be/', 10);
        $this->assertTrue(is_array($downloadResults));
        $this->assertSame('http://spatie.be/', $downloadResults['inputDomain']);
        $this->assertSame('spatie.be:443', $downloadResults['tested']);
        $downloadResults = null;

        $downloadResults = Downloader::downloadCertificateFromUrl('http://www.spatie.be/', 10);
        $this->assertTrue(is_array($downloadResults));
        $this->assertSame('http://www.spatie.be/', $downloadResults['inputDomain']);
        $this->assertSame('www.spatie.be:443', $downloadResults['tested']);
    }

    /** @test */
    public function it_can_throw_ssl_errors_correctly()
    {
        $this->expectException(CouldNotDownloadCertificate::class);
        $this->expectExceptionMessage('Server SSL handshake error – the certificate for `rc4.badssl.com:443` will not work.');
        Downloader::downloadCertificateFromUrl('rc4.badssl.com', 10);

        $this->expectException(CouldNotDownloadCertificate::class);
        $this->expectExceptionMessage('Server does not support SSL over port 80.');
        Downloader::downloadCertificateFromUrl('selfsigned.badssl.com:80', 10);
    }

    /** @test */
    public function it_throws_an_exception_for_non_existing_host()
    {
        $this->expectException(InvalidUrl::class);

        Downloader::downloadCertificateFromUrl('spatie-non-existing.be');
    }

    /** @test */
    public function it_throws_an_exception_when_downloading_a_certificate_from_wrong_port()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('www.kutfilm.be:80');
    }

    /** @test */
    public function it_throws_an_exception_when_downloading_a_certificate_from_an_outdated_host()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('rc4.badssl.com', 10);
    }

    /** @test */
    public function it_throws_a_timeout_exception_when_downloading_a_certificate_from_a_fake_location()
    {
        $this->expectException(CouldNotDownloadCertificate::class);

        Downloader::downloadCertificateFromUrl('10.0.0.1', 3);
    }
}
