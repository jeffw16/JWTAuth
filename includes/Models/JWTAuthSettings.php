<?php
namespace MediaWiki\Extension\JWTAuth\Models;

use InvalidArgumentException;
use MediaWiki\Extension\JWTAuth\JWTHandler;
use Wikimedia\Assert\Assert;

class JWTAuthSettings {
    private string $algorithm;
    private string $key;
    private array $requiredClaims;

    private function __construct() {}

    public static function initialize(
        string $algorithm,
        string $key,
        array $requiredClaims
    ): JWTAuthSettings {
        if (empty($algorithm) || empty($key)) {
            throw new InvalidArgumentException();
        }

        Assert::precondition(
            in_array($algorithm, JWTHandler::JWT_SUPPORTED_ALGORITHMS, true)
            , 'JWT algorithm must be one of the following: HS256, RS256, EdDSA, but was found to be "' . $algorithm . '".'
        );

        $jwtAuthSettings = new JWTAuthSettings();
        $jwtAuthSettings->algorithm = $algorithm;
        $jwtAuthSettings->key = $key;
        $jwtAuthSettings->requiredClaims = $requiredClaims;

        return $jwtAuthSettings;
    }

    public function getAlgorithm(): string {
        return $this->algorithm;
    }

    public function getKey(): string {
        return $this->key;
    }

    public function getRequiredClaims(): array {
        return $this->requiredClaims;
    }
}
