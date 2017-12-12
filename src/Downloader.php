<?php

namespace LiquidWeb\SslCertificate;

use Throwable;
use phpseclib\File\X509;
use LiquidWeb\SslCertificate\Exceptions\Handler;

class Downloader
{
    public static function downloadCertificateFromUrl(string $url, int $timeout = 30): array
    {
        // Trusted variable to keep track of SSL trust
        $trusted = true;
        $sslConfig = StreamConfig::configSecure();
        $parsedUrl = new Url($url);
        $client = null;

        try {
            $client = stream_socket_client(
                "ssl://{$parsedUrl->getTestURL()}",
                $errorNumber,
                $errorDescription,
                $timeout,
                STREAM_CLIENT_CONNECT,
                $sslConfig->getContext()
            );
            unset($sslConfig);
        } catch (Throwable $thrown) {
            // Try agian in insecure mode
            $sslConfig = StreamConfig::configInsecure();
            $trusted = false;

            try {
                // As the URL failed verification we set to false
                $client = stream_socket_client(
                    "ssl://{$parsedUrl->getTestURL()}",
                    $errorNumber,
                    $errorDescription,
                    $timeout,
                    STREAM_CLIENT_CONNECT,
                    $sslConfig->getContext()
                );
                unset($sslConfig);
            } catch (Throwable $thrown) {
                (new Handler($thrown))->downloadHandler($parsedUrl);
            }
        }

        return self::prepareCertificateResponse($client, $trusted, $parsedUrl);
    }

    private static function prepareCertificateResponse($resultClient, bool $trusted, Url $parsedUrl): array
    {
        $response = stream_context_get_options($resultClient);
        $connectionInfo = stream_get_meta_data($resultClient)['crypto'];
        unset($resultClient);
        $mainCert = openssl_x509_parse($response['ssl']['peer_certificate'], true);

        $full_chain = [];
        if (count($response['ssl']['peer_certificate_chain']) > 1) {
            foreach ($response['ssl']['peer_certificate_chain'] as $cert) {
                $parsedCert = openssl_x509_parse($cert, true);
                $isChain = ! ($parsedCert['hash'] === $mainCert['hash']);
                if ($isChain === true) {
                    array_push($full_chain, $parsedCert);
                }
            }
        }

        return [
            'inputDomain' => $parsedUrl->getInputUrl(),
            'tested' => $parsedUrl->getTestURL(),
            'trusted' => $trusted,
            'dns-resolves-to' => $parsedUrl->getIp(),
            'cert' => $mainCert,
            'full_chain' => $full_chain,
            'connection' => $connectionInfo,
        ];
    }

    public static function downloadRevocationListFromUrl(string $url): array
    {
        $parsedUrl = new Url($url);
        $csrConfig = StreamConfig::configCrl();
        $file = file_get_contents($parsedUrl->getValidatedURL(), false, $csrConfig->getContext());
        unset($csrConfig, $parsedUrl);
        $x509 = new X509();
        $crl = $x509->loadCRL($file);
        unset($x509, $file);

        return $crl;
    }
}
