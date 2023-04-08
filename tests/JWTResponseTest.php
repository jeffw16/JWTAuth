<?php
// BEGIN: xh7d3f8c4jw9
use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use PHPUnit\Framework\TestCase;

class JWTResponseTest extends TestCase {
    private JWTAuthSettings $settings;

    protected function setUp(): void {
        $this->settings = new JWTAuthSettings('secret', 'HS256', 3600);
    }

    public function testBuildJWTResponse(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings);

        $this->assertInstanceOf(JWTResponse::class, $jwtResponse);
        $this->assertSame($this->settings, $jwtResponse->getSettings());
    }

    public function testGetUsername(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setUsername('testuser');

        $this->assertSame('Testuser', $jwtResponse->getUsername());
    }

    public function testGetUsernameWithEmailAddress(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setEmailAddress('testuser@example.com');

        $this->assertSame('Testuser', $jwtResponse->getUsername());
    }

    public function testGetUsernameWithFullName(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setFirstName('Test')
            ->setLastName('User');

        $this->assertSame('TestUser', $jwtResponse->getUsername());
    }

    public function testGetEmailAddress(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setEmailAddress('testuser@example.com');

        $this->assertSame('testuser@example.com', $jwtResponse->getEmailAddress());
    }

    public function testGetFirstName(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setFirstName('Test');

        $this->assertSame('Test', $jwtResponse->getFirstName());
    }

    public function testGetLastName(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setLastName('User');

        $this->assertSame('User', $jwtResponse->getLastName());
    }

    public function testGetFullName(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setFirstName('Test')
            ->setLastName('User');

        $this->assertSame('Test User', $jwtResponse->getFullName());
    }

    public function testGetIssuer(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setIssuer('example.com');

        $this->assertSame('example.com', $jwtResponse->getIssuer());
    }

    public function testGetAudience(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setAudience('example.com');

        $this->assertSame('example.com', $jwtResponse->getAudience());
    }

    public function testGetSubject(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setSubject('test');

        $this->assertSame('test', $jwtResponse->getSubject());
    }

    public function testGetExternalUserID(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setExternalUserID('123');

        $this->assertSame('123', $jwtResponse->getExternalUserID());
    }

    public function testGetGroups(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setGroups(['group1', 'group2']);

        $this->assertSame(['group1', 'group2'], $jwtResponse->getGroups());
    }

    public function testSetUsername(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setUsername('testuser');

        $this->assertSame('Testuser', $jwtResponse->getUsername());
    }

    public function testSetFirstName(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setFirstName('Test');

        $this->assertSame('Test', $jwtResponse->getFirstName());
    }

    public function testSetLastName(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setLastName('User');

        $this->assertSame('User', $jwtResponse->getLastName());
    }

    public function testSetEmailAddress(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setEmailAddress('testuser@example.com');

        $this->assertSame('testuser@example.com', $jwtResponse->getEmailAddress());
    }

    public function testSetIssuer(): void {
        $jwtResponse = JWTResponse::buildJWTResponse($this->settings)
            ->setIssuer('example.com');

        $this->assertSame('example.com', $jwtResponse->getIssuer());
    }
}
// END: xh7d3f8c4jw9