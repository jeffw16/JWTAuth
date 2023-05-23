<?php
// BEGIN: f5a7d1d5c5e7
use MediaWiki\Extension\JWTAuth\JWTHandler;
use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use MediaWiki\Logger\LoggerFactory;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

class JWTHandlerTest extends TestCase {
    private JWTHandler $jwtHandler;
    private JWTAuthSettings $jwtSettings;
    private LoggerInterface $logger;

    protected function setUp(): void {
        $this->jwtSettings = new JWTAuthSettings(
            'HS256',
            'secret_key',
            'issuer',
            'audience',
            'subject',
            'username',
            'email',
            'firstName',
            'lastName',
            'groups'
        );
        $this->logger = LoggerFactory::getInstance('JWTAuth');
        $this->jwtHandler = new JWTHandler($this->jwtSettings, $this->logger);
    }

    public function testPreprocessRawJWTData(): void {
        $rawJWTData = 'Bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $expectedCleanJWTData = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $cleanJWTData = $this->jwtHandler->preprocessRawJWTData($rawJWTData);
        $this->assertEquals($expectedCleanJWTData, $cleanJWTData);
    }

    public function testProcessJWT(): void {
        $rawJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
        $expectedJWTResponse = JWTResponse::buildJWTResponse($this->jwtSettings)
                                    ->setUsername('John Doe')
                                    ->setEmailAddress('')
                                    ->setExternalUserID('')
                                    ->setFirstName('John')
                                    ->setLastName('Doe')
                                    ->setIssuer('issuer')
                                    ->setAudience('audience')
                                    ->setSubject('subject')
                                    ->setGroups('');
        $jwtResponse = $this->jwtHandler->processJWT($rawJWT);
        $this->assertEquals($expectedJWTResponse, $jwtResponse);
    }
}
// END: f5a7d1d5c5e7