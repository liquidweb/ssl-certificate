# Changelog

All notable changes to `ssl-certificate` will be documented in this file

## 2.0.0 - 2016-12-12

- Update CHANGELOG.md file
- Add etsy/phan support
- Add PHPStan as require-dev
- Better PHPDocs and Coding standards all over
- Updated tests to match code changes
- Refactor SslCertificate revoked status related code
    - Made isClrRevoked private, was previously public
    - Added new public function isRevoked

## 1.1.3 - 2016-12-12

- Damage control version; set to an older point than 1.1.2 in order to ensure proper versioning.

## 1.1.2 - 2016-12-12

- Accidental release; meant to be a Major version bump as some changes are not backwards-compatible.

## 1.1.1 - Never Released

- Update README.md file
- Improve logic, reduce assumptions
- Add more return types; also add commented ones for PHP 7.1

## 1.1.0 - Never Released

- Refactor Url class; use league parser
- Does contain non-breaking API changes
    - verifyDNS => verifyAndGetDNS
    - Added: getValidatedURL
- Basic code style fixes

## 1.0.3 - Never Released

- Update composer test command shortcut
- Adjust some logic for SSL chains
- Update helper functions
- Update tests for Url and Downloader

## 1.0.2 - Never Released

- Update PHPunit test configs
- Add humbug support
- Update Downloader tests
- Fix automated tests

## 1.0.1 - 2016-09-19

- Pushed to composer, so update the README.md

## 1.0.0 - 2016-09-19

- package forked
- reset semver
- removed previous package tags
- added `SslChain.php`
- added `SslRevocationList.php`
- added `StreamConfig.php`
- added `IssuerMeta.php`
- added the following functions:
    - InvalidUrl `couldNotResolveDns`
    - CouldNotDownloadCertificate `failedHandshake`
    - CouldNotDownloadCertificate `connectionTimeout`
    - Downloader `prepareCertificateResponse` - private
    - Downloader `downloadRevocationListFromUrl`
    - Url `getValidatedURL`
    - Url `getPort`
    - Url `getTestURL`
    - Url `getIp`
    - SslCertificate `extractCrlLinks` - private
    - SslCertificate `setcrlLinks` - private
    - SslCertificate `getRevokedDate` - private
    - SslCertificate `parseCertChains` - private
    - SslCertificate `hasSslChain`
    - SslCertificate `getTestedDomain`
    - SslCertificate `getCertificateChains`
    - SslCertificate `getSerialNumber`
    - SslCertificate `hasCrlLink`
    - SslCertificate `getCrlLinks`
    - SslCertificate `getCrl`
    - SslCertificate `isClrRevoked`
    - SslCertificate `getResolvedIp`
    - SslCertificate `getConnectionMeta`
    - SslCertificate `isTrusted`
- added `SslChainTest.php`
- added various stubs for Testing
- updated all tests to maintain high coverage levels

# Original package history

## 1.2.0 - 2016-08-20

- added `getSignatureAlgorithm`

## 1.1.0 - 2016-07-29

- added `isValidUntil`

## 1.0.0 - 2016-07-28

- initial release
