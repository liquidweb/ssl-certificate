<?php

namespace LiquidWeb\SslCertificate\Exceptions;

use Exception;

final class InvalidUrl extends Exception
{
    use TrackDomainTrait;

    public static function couldNotValidate(string $url): self
    {
        $exception = new static("String `{$url}` is not a valid url.");

        return $exception;
    }

    public static function couldNotDetermineHost(string $url): self
    {
        $exception = new static("Could not determine host from url `{$url}`.");

        return $exception;
    }

    public static function couldNotResolveDns(string $hostName): self
    {
        $exception = new static("The domain `{$hostName}` does not have a valid DNS record.");
        $exception->setErrorDomain($hostName);

        return $exception;
    }
}
