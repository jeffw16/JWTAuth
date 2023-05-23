<?php
// BEGIN: f1a2b3c4d5e6

use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use PHPUnit\Framework\TestCase;

class JWTAuthSettingsTest extends TestCase {
    public function testInitialize(): void {
        $algorithm = 'HS256';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        $jwtAuthSettings = JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);

        $this->assertInstanceOf(JWTAuthSettings::class, $jwtAuthSettings);
        $this->assertEquals($algorithm, $jwtAuthSettings->getAlgorithm());
        $this->assertEquals($key, $jwtAuthSettings->getKey());
        $this->assertEquals($requiredClaims, $jwtAuthSettings->getRequiredClaims());
        $this->assertEquals($groupMapping, $jwtAuthSettings->getGroupMapping());
    }

    public function testInitializeWithInvalidAlgorithm(): void {
        $this->expectException(InvalidArgumentException::class);

        $algorithm = 'invalid';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);
    }

    public function testInitializeWithEmptyAlgorithm(): void {
        $this->expectException(InvalidArgumentException::class);

        $algorithm = '';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);
    }

    public function testInitializeWithEmptyKey(): void {
        $this->expectException(InvalidArgumentException::class);

        $algorithm = 'HS256';
        $key = '';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);
    }

    public function testInitializeWithNullGroupMapping(): void {
        $algorithm = 'HS256';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = null;

        $jwtAuthSettings = JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);

        $this->assertInstanceOf(JWTAuthSettings::class, $jwtAuthSettings);
        $this->assertEquals($algorithm, $jwtAuthSettings->getAlgorithm());
        $this->assertEquals($key, $jwtAuthSettings->getKey());
        $this->assertEquals($requiredClaims, $jwtAuthSettings->getRequiredClaims());
        $this->assertEquals([], $jwtAuthSettings->getGroupMapping());
    }
}
// END: f1a2b3c4d5e6
// BEGIN: jh4d5f6g7h8j

class JWTAuthSettingsTestTwo extends TestCase {
    public function testInitialize(): void {
        $algorithm = 'HS256';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        $jwtAuthSettings = JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);

        $this->assertInstanceOf(JWTAuthSettings::class, $jwtAuthSettings);
        $this->assertEquals($algorithm, $jwtAuthSettings->getAlgorithm());
        $this->assertEquals($key, $jwtAuthSettings->getKey());
        $this->assertEquals($requiredClaims, $jwtAuthSettings->getRequiredClaims());
        $this->assertEquals($groupMapping, $jwtAuthSettings->getGroupMapping());
    }

    public function testInitializeWithInvalidAlgorithm(): void {
        $this->expectException(InvalidArgumentException::class);

        $algorithm = 'invalid';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);
    }

    public function testInitializeWithEmptyAlgorithm(): void {
        $this->expectException(InvalidArgumentException::class);

        $algorithm = '';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);
    }

    public function testInitializeWithEmptyKey(): void {
        $this->expectException(InvalidArgumentException::class);

        $algorithm = 'HS256';
        $key = '';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = ['admin' => 'sysop'];

        JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);
    }

    public function testInitializeWithNullGroupMapping(): void {
        $algorithm = 'HS256';
        $key = 'secret';
        $requiredClaims = ['sub', 'exp'];
        $groupMapping = null;

        $jwtAuthSettings = JWTAuthSettings::initialize($algorithm, $key, $requiredClaims, $groupMapping);

        $this->assertInstanceOf(JWTAuthSettings::class, $jwtAuthSettings);
        $this->assertEquals($algorithm, $jwtAuthSettings->getAlgorithm());
        $this->assertEquals($key, $jwtAuthSettings->getKey());
        $this->assertEquals($requiredClaims, $jwtAuthSettings->getRequiredClaims());
        $this->assertEquals([], $jwtAuthSettings->getGroupMapping());
    }
}
// END: jh4d5f6g7h8j