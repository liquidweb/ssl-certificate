<?php

namespace LiquidWeb\SslCertificate\Test;

use \PHPUnit\Framework\TestCase;
use LiquidWeb\SslCertificate\Url;
use LiquidWeb\SslCertificate\Downloader;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;
use LiquidWeb\SslCertificate\Exceptions\CouldNotDownloadCertificate;

class ExceptionTest extends TestCase
{
    /** @test */
    public function it_can_throw_invalid_url_exceptions_dns()
    {
        $this->expectException(InvalidUrl::class);
        $url = new Url('http://googlecom');
    }

    /** @test */
    public function it_can_use_the_handler_to_throw_exceptions()
    {
        $this->expectException(CouldNotDownloadCertificate::class);
        $cert = Downloader::downloadCertificateFromUrl('rc4.badssl.com', 5);
    }
}
