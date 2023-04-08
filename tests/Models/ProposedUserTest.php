<?php
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use MediaWiki\Extension\JWTAuth\Models\ProposedUser;
use MediaWiki\Session\Session;
use MediaWiki\User\UserGroupManager;
use Psr\Log\LoggerInterface;
use User;
use Wikimedia\Timestamp\ConvertibleTimestamp;

class ProposedUserTest extends \PHPUnit\Framework\TestCase {
    public function testMakeUserFromJWTResponse() {
        $jwtResponse = $this->createMock(JWTResponse::class);
        $jwtResponse->method('getUsername')->willReturn('testuser');
        $jwtResponse->method('getEmailAddress')->willReturn('testuser@example.com');
        $jwtResponse->method('getFullName')->willReturn('Test User');
        $jwtResponse->method('getGroups')->willReturn(['group1', 'group2']);

        $userGroupManager = $this->createMock(UserGroupManager::class);
        $userGroupManager->expects($this->exactly(2))
            ->method('addUserToGroup')
            ->withConsecutive(
                [$this->isInstanceOf(User::class), 'group1'],
                [$this->isInstanceOf(User::class), 'group2']
            );

        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->exactly(4))
            ->method('debug')
            ->withConsecutive(
                ['testuser does not exist; attempting to creating user'],
                ['Add groups: ' . print_r(['group1', 'group2'], true)],
                ['Proposed user formed and ready: ' . print_r($this->isInstanceOf(User::class), true)],
                ['Global session acquired.']
            );

        $proposedUser = $this->createMock(User::class);
        $proposedUser->method('getId')->willReturn(0);
        $proposedUser->method('loadDefaults')->willReturnSelf();
        $proposedUser->method('setRealName')->willReturnSelf();
        $proposedUser->method('addToDatabase')->willReturnSelf();

        $session = $this->createMock(Session::class);
        $session->expects($this->once())
            ->method('persist');
        $session->expects($this->once())
            ->method('setUser')
            ->with($proposedUser);

        $proposedUserObject = ProposedUser::makeUserFromJWTResponse(
            $jwtResponse,
            $userGroupManager,
            $logger
        );

        $this->assertInstanceOf(ProposedUser::class, $proposedUserObject);

        $proposedUserObject->setUserInSession($session);
    }

    public function testSetUserInSession() {
        $proposedUser = $this->createMock(User::class);
        $session = $this->createMock(Session::class);
        $logger = $this->createMock(LoggerInterface::class);

        $proposedUserObject = new ProposedUser(
            $proposedUser,
            $logger
        );

        $session->expects($this->once())
            ->method('persist');
        $session->expects($this->once())
            ->method('setUser')
            ->with($proposedUser);

        $proposedUserObject->setUserInSession($session);
    }
}