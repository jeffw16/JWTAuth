<?php
namespace MediaWiki\Extension\JWTAuth\Models;

use MediaWiki\Extension\JWTAuth\JWTAuth;
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use MediaWiki\Session\Session;
use MediaWiki\User\UserGroupManager;
use Psr\Log\LoggerInterface;
use User;
use Wikimedia\Timestamp\ConvertibleTimestamp;

class ProposedUser {
    private User $proposedUser;

    private LoggerInterface $logger;

    private function __construct(
        User $proposedUser,
        LoggerInterface $logger
    ) {
        $this->proposedUser = $proposedUser;
        $this->logger = $logger;
    }

    public static function makeUserFromJWTResponse(
        JWTResponse $jwtResponse,
        UserGroupManager $userGroupManager,
        LoggerInterface $logger
    ): ProposedUser {
        $username = $jwtResponse->getUsername();
        $email = $jwtResponse->getEmailAddress();
        $realname = $jwtResponse->getFullName();

        $proposedUser = User::newFromName($username);

        if ($proposedUser !== false && $proposedUser->getId() != 0) {
            $logger->debug("$username does exist with an ID " . $proposedUser->getId());
            $proposedUser->mId = $proposedUser->getId();
            $proposedUser->loadFromId();
        } else {
            // TODO: use autoCreateUser in https://gerrit.wikimedia.org/g/mediawiki/core/+/64c6ce7b95188ad381ee947b726fadde6aafe1c1/includes/auth/AuthManager.php
            $logger->debug("$username does not exist; attempting to creating user");
            $proposedUser->loadDefaults($username);
            $proposedUser->mName = $username;
            if ($realname !== null) {
                $proposedUser->setRealName($realname);
            }
            $proposedUser->mEmail = $email;
            $now = ConvertibleTimestamp::now(TS_UNIX);
            $proposedUser->mEmailAuthenticated = $now;
            $proposedUser->mTouched = $now;
            $proposedUser->addToDatabase();
        }

        $groupsToBeAdded = $jwtResponse->getGroups();
        $logger->debug("Add groups: " . print_r($groupsToBeAdded, true));
        foreach ($groupsToBeAdded as $group) {
            $userGroupManager->addUserToGroup($proposedUser, $group);
        }

        $logger->debug("Proposed user formed and ready: " . print_r($proposedUser, true));

        $proposedUserObject = new ProposedUser(
            $proposedUser,
            $logger
        );

        return $proposedUserObject;
    }

    public function setUserInSession(
        Session $globalSession
    ): void {
        // Need to persist the session.
        $globalSession->persist();

        $this->logger->debug("Global session acquired.");

        $globalSession->setUser($this->proposedUser);

        $this->logger->debug("Set user in global session.");
        $this->logger->debug("The user in global session is now: " . print_r($globalSession->getUser(), true));
    }
}
