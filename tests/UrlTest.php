<?php

namespace LiquidWeb\SslCertificate\Test;

use PHPUnit\Framework\TestCase;
use LiquidWeb\SslCertificate\Url;
use LiquidWeb\SslCertificate\Exceptions\InvalidUrl;

class UrlTest extends TestCase
{
    /** @test */
    public function it_can_determine_a_host_name()
    {
        $url = new Url('https://spatie.be/opensource');

        $this->assertSame('spatie.be', $url->getHostName());
    }

    /** @test */
    public function it_can_determine_a_host_name_when_not_specifying_a_protocol()
    {
        $url = new Url('spatie.be');

        $this->assertSame('spatie.be', $url->getHostName());
    }

    /** @test */
    public function it_throws_an_exception_when_creating_an_url_from_an_empty_string()
    {
        $this->expectException(InvalidUrl::class);

        new Url('');
    }

    /** @test */
    public function it_can_determine_a_host_ip()
    {
        $url = new Url('https://spatie.be/opensource');

        $this->assertSame('138.197.187.74', $url->getIp());
    }
}
