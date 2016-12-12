# A php package to validate SSL certificates

This package was inspired by, and forked from, the original [spatie/ssl-certificate](https://github.com/spatie/ssl-certificate) SSL certificate data validation and query class. Where this package differs is the scope of validation and intended goals. This package takes the SSL certificate validation a few steps further than the original class that inspired it.

This variant is able to detect if an ssl is:
* trusted in a browser,
* a match for the domain tested,
* valid in a general sense,
* providing additional chains,
* and even if the SSL is CRL revoked.

Additionally, this package tracks and provides methods to view SSL Chain information.

Here are a few examples:

```php
$certificate = SslCertificate::createForHostName('liquidweb.com');

$certificate->getIssuer(); // returns "GlobalSign Extended Validation CA - SHA256 - G2"
$certificate->isValid(); // returns true if the certificate is currently valid
$certificate->isTrusted(); // returns true if the certificate is trusted by default
$certificate->isRevoked(); // returns bool of revoked status, or null if no list provided
$certificate->hasSslChain(); // returns bool of ssl chain status
$certificate->expirationDate(); // returns an instance of Carbon
$certificate->expirationDate()->diffInDays(); // returns an int
$certificate->getSignatureAlgorithm(); // returns a string
$certificate->getSerialNumber(); // returns a string
```

## Installation

You can install the package via composer:

```bash
composer require liquidweb/ssl-certificate
```

## Usage

You can create an instance of `LiquidWeb\SslCertificate\SslCertificate` with this named constructor:

```php
$certificate = SslCertificate::createForHostName('liquidweb.com');
```

If the given `hostName` is invalid `LiquidWeb\SslCertificate\InvalidUrl` will be thrown.

If the given `hostName` is valid but there was a problem downloading the certifcate `LiquidWeb\SslCertificate\CouldNotDownloadCertificate` will be thrown.

### Getting the issuer name

```php
$certificate->getIssuer(); // returns "GlobalSign Extended Validation CA - SHA256 - G2"
```

### Getting the domain name

Returns the primary domain name for the certificate

```php
$certificate->getDomain(); // returns "www.liquidweb.com"
```

### Getting the certificate's signing algorithm

Returns the algorithm used for signing the certificate

```php
$certificate->getSignatureAlgorithm(); // returns "RSA-SHA256"
```

### Getting the additional domain names

A certificate can cover multiple (sub)domains. Here's how to get them.

```php
$certificate->getAdditionalDomains(); // returns [
                                                    "www.liquidweb.com",
                                                    "www.stormondemand.com",
                                                    "www.sonet7.com",
                                                    "manage.stormondemand.com",
                                                    "manage.liquidweb.com",
                                                    "liquidweb.com"
                                                ]
```

A domain name return with this method can start with `*` meaning it is valid for all subdomains of that domain.

### Getting the date when the certificate becomes valid

```php
$certificate->validFromDate(); // returns an instance of Carbon
```

### Getting the expiration date

```php
$certificate->expirationDate(); // returns an instance of Carbon
```

### Determining if the certificate is still valid

Returns true if the current Date and time is between `validFromDate` and `expirationDate`.

```php
$certificate->isValid(); // returns a boolean
```

You also use this method to determine if a given domain is covered by the certificate. Of course it'll keep checking if the current Date and time is between `validFromDate` and `expirationDate`.

```php
$certificate->isValid('liquidweb.com'); // returns true;
$certificate->isValid('spatie.be'); // returns false;
```

### Determining if the certificate is still valid until a given date

Returns true if the certificate is valid and if the `expirationDate` is before the given date.

```php
$certificate->isValidUntil(Carbon::now()->addDays(7)); // returns a boolean
```

### Determining if the certificate is expired

```php
$certificate->isExpired(); // returns a boolean if expired
```

## Changelog

Please see [CHANGELOG](CHANGELOG.md) for more information what has changed recently.

## Testing

``` bash
$ composer test
```

Note: When working to test your implementation of this library you can use [BadSSL](https://badssl.com/) to simulate various SSL scenarios.

## Credits

- [Dan Pock](https://github.com/mallardduck) - Fork Creator & Maintainer
- [Freek Van der Herten](https://github.com/freekmurze) - Original package creator
- [All Contributors](../../contributors)

The helper functions and tests were copied from the [Laravel Framework](https://github.com/laravel/framework).

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
