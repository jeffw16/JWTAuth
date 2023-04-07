<?php
namespace MediaWiki\Extension\JWTAuth\Models;

use MediaWiki\Extension\JWTAuth\JWTAuth;
use Wikimedia\Assert\Assert;

class JWTAuthSettings {
    private string $algorithm;
    private string $key;
    private array $requiredClaims;
    private array $groupMapping;

    private function __construct() {}

    public static function initialize(
        string $algorithm,
        string $key,
        array $requiredClaims,
        array $groupMapping,
	string $claimName
    ): JWTAuthSettings {
        if (empty($algorithm) || empty($key)) {
            throw new InvalidArgumentException();
        }

        Assert::precondition(
            in_array($algorithm, JWTAuth::JWT_SUPPORTED_ALGORITHMS, true)
            , 'JWT algorithm must be one of the following: HS256, RS256, EdDSA, but was found to be "' . $algorithm . '".'
        );

        if ($groupMapping === null) {
            $groupMapping = [];
        }

        $jwtAuthSettings = new JWTAuthSettings();
        $jwtAuthSettings->algorithm = $algorithm;
        $jwtAuthSettings->key = $key;
        $jwtAuthSettings->requiredClaims = $requiredClaims;
        $jwtAuthSettings->groupMapping = $groupMapping;
        $jwtAuthSettings->groupsClaimName = $claimName;

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

    public function getGroupMapping(): array {
        return $this->groupMapping;
    }

    public function getGroupsClaimName(): string {
        return $this->groupsClaimName ?? JWTAuth::CLAIM_NAMES['groups'];
    }
}
