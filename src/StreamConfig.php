<?php

namespace LiquidWeb\SslCertificate;

class StreamConfig
{
    /**
     * The stream settings for the client.
     *
     * @return A stream context resource.
     */
    protected $streamContext;

    public static function configSecure(): self
    {
        $streamContext = stream_context_create(
            [
                'ssl' => [
                    'capture_peer_cert' => true,
                    'capture_peer_cert_chain' => true,
                    'disable_compression' => true,
                ],
            ]
        );

        return new static($streamContext);
    }

    public static function configInsecure(): self
    {
        $streamContext = stream_context_create(
            [
                'ssl' => [
                    'allow_self_signed' => true,
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'capture_peer_cert' => true,
                    'capture_peer_cert_chain' => true,
                    'disable_compression' => true,
                ],
            ]
        );

        return new static($streamContext);
    }

    public static function configCrl(): self
    {
        $streamContext = stream_context_create(
            [
            'http' => [
                'method' => 'GET',
                'max_redirects' => '0',
                'ignore_errors' => '1',
                ],
            ]
        );

        return new static($streamContext);
    }

    public function __construct($streamContext)
    {
        $this->streamContext = $streamContext;
    }

    public function getContext()
    {
        return $this->streamContext;
    }
}
