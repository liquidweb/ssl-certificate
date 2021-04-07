<?php

namespace LiquidWeb\SslCertificate;

final class IssuerMeta
{
    protected $commonName;
    protected $countryName;
    protected $organizationName;
    protected $organizationUnitName;

    public static function fromRdnSequence(array $input): self
    {
        $items = [];
        foreach ($input as $arr) {
            // Get the actual item
            $rawItem = $arr[0];
            $type = explode('id-at-', $rawItem['type'])[1];
            $value = $rawItem['value']['printableString'];
            $items[$type] = $value;
        }

        return new static($items);
    }

    public function __construct(array $input = [])
    {
        $this->commonName = isset($input['commonName']) ? $input['commonName'] : '';
        $this->countryName = ($input['countryName']) ? $input['countryName'] : '';
        $this->organizationName = isset($input['organizationName']) ? $input['organizationName'] : '';
        $this->organizationUnitName = isset($input['organizationalUnitName']) ? $input['organizationalUnitName'] : '';
    }
}
