<?php

namespace LiquidWeb\SslCertificate\Test;

use PHPUnit\Framework\TestCase;

class HelpersTest extends TestCase
{
    /** @test */
    public function it_can_determine_if_a_string_starts_with_a_given_string()
    {
        $this->assertTrue(\LiquidWeb\SslCertificate\starts_with('jason', 'jas'));
        $this->assertTrue(\LiquidWeb\SslCertificate\starts_with('jason', 'jason'));
        $this->assertTrue(\LiquidWeb\SslCertificate\starts_with('jason', ['jas']));
        $this->assertTrue(\LiquidWeb\SslCertificate\starts_with('jason', ['day', 'jas']));
        $this->assertFalse(\LiquidWeb\SslCertificate\starts_with('jason', 'day'));
        $this->assertFalse(\LiquidWeb\SslCertificate\starts_with('jason', ['day']));
        $this->assertFalse(\LiquidWeb\SslCertificate\starts_with('jason', ''));
    }

    /** @test */
    public function it_can_determine_if_a_string_end_with_a_given_string()
    {
        $this->assertTrue(\LiquidWeb\SslCertificate\ends_with('jason', 'on'));
        $this->assertTrue(\LiquidWeb\SslCertificate\ends_with('jason', 'jason'));
        $this->assertTrue(\LiquidWeb\SslCertificate\ends_with('jason', ['on']));
        $this->assertTrue(\LiquidWeb\SslCertificate\ends_with('jason', ['no', 'on']));
        $this->assertFalse(\LiquidWeb\SslCertificate\ends_with('jason', 'no'));
        $this->assertFalse(\LiquidWeb\SslCertificate\ends_with('jason', ['no']));
        $this->assertFalse(\LiquidWeb\SslCertificate\ends_with('jason', ''));
        $this->assertFalse(\LiquidWeb\SslCertificate\ends_with('7', ' 7'));
    }

    /** @test */
    public function it_can_create_substring_of_a_given_stirng()
    {
        $this->assertEquals('Ё', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', -1));
        $this->assertEquals('ЛЁ', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', -2));
        $this->assertEquals('И', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', -3, 1));
        $this->assertEquals('ДЖИЛ', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', 2, -1));
        $this->assertEmpty(\LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', 4, -4));
        $this->assertEquals('ИЛ', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', -3, -1));
        $this->assertEquals('ГДЖИЛЁ', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', 1));
        $this->assertEquals('ГДЖ', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', 1, 3));
        $this->assertEquals('БГДЖ', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', 0, 4));
        $this->assertEquals('Ё', \LiquidWeb\SslCertificate\substr('БГДЖИЛЁ', -1, 1));
        $this->assertEmpty(\LiquidWeb\SslCertificate\substr('Б', 2));
    }

    /** @test */
    public function it_can_determine_the_lenght_of_a_string()
    {
        $this->assertEquals(11, \LiquidWeb\SslCertificate\length('foo bar baz'));
        $this->assertEquals(6, \LiquidWeb\SslCertificate\length('google'));
        $this->assertEquals(9, \LiquidWeb\SslCertificate\length('123456789'));
        $this->assertEquals(10, \LiquidWeb\SslCertificate\length('1234567890'));
        $this->assertTrue(\LiquidWeb\SslCertificate\length('1234567890') === 10);
        $this->assertFalse(\LiquidWeb\SslCertificate\length('123456789') === 42);
    }

    /** @test */
    public function it_can_determine_if_a_string_str_contains_another_string()
    {
        $this->assertTrue(\LiquidWeb\SslCertificate\str_contains('taylor', 'ylo'));
        $this->assertTrue(\LiquidWeb\SslCertificate\str_contains('taylor', 'taylor'));
        $this->assertTrue(\LiquidWeb\SslCertificate\str_contains('taylor', ['ylo']));
        $this->assertTrue(\LiquidWeb\SslCertificate\str_contains('taylor', ['xxx', 'ylo']));
        $this->assertFalse(\LiquidWeb\SslCertificate\str_contains('taylor', 'xxx'));
        $this->assertFalse(\LiquidWeb\SslCertificate\str_contains('taylor', ['xxx']));
        $this->assertFalse(\LiquidWeb\SslCertificate\str_contains('taylor', ''));
    }
}
