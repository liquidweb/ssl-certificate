<?php

namespace LiquidWeb\SslCertificate\Exceptions;

use Exception;
use LiquidWeb\SslCertificate\Url;

final class CouldNotDownloadCertificate extends Exception
{
    use TrackDomainTrait;

    public static function hostDoesNotExist(string $hostName): self
    {
        $exception = new static("The host named `{$hostName}` does not exist.");
        $exception->setErrorDomain($hostName);

        return $exception;
    }

    public static function noCertificateInstalled(string $hostName): self
    {
        $exception = new static("Could not find a certificate on  host named `{$hostName}`.");
        $exception->setErrorDomain($hostName);

        return $exception;
    }

    public static function failedHandshake(Url $url): self
    {
        if ($url->getPort() === '80') {
            return new static('Server does not support SSL over port 80.');
        }
        $exception = new static("Server SSL handshake error – the certificate for `{$url->getTestURL()}` will not work.");
        $exception->setErrorDomain($url->getHostName());

        return $exception;
    }

    public static function connectionTimeout(string $hostName): self
    {
        $exception = new static("Connection timed out while testing `{$hostName}`.");
        $exception->setErrorDomain($hostName);

        return $exception;
    }

    public static function unknownError(string $hostName, string $errorMessage): self
    {
        $exception = new static("Could not download certificate for host `{$hostName}` because {$errorMessage}");
        $exception->setErrorDomain($hostName);

        return $exception;
    }
}
