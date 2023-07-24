<?php
namespace MediaWiki\Extension\JWTAuth;

use Config;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserIdentityLookup;
use Message;
use Title;

class JWTAuth extends PluggableAuth {
	const JWTAUTH_POST_PARAMETER = 'Authorization';
	const JWTAUTH_SUBJECT_SESSION_KEY = 'JWTAuthSubject';
	const JWTAUTH_ISSUER_SESSION_KEY = 'JWTAuthIssuer';
	const JWTAUTH_ATTRIBUTES_SESSION_KEY = 'JWTAuthAttributes';

	private Config $mainConfig;
	private AuthManager $authManager;
	private JWTHandler $jwtHandler;
	private UserIdentityLookup $userIdentityLookup;
	private JWTAuthStore $jwtAuthStore;
	private bool $migrateUsersByEmail;
	private bool $migrateUsersByUserName;
	private bool $useRealNameAsUserName;
	private bool $useEmailNameAsUserName;

	/**
	 * @param Config $mainConfig
	 * @param AuthManager $authManager
	 * @param UserIdentityLookup $userIdentityLookup
	 * @param JWTAuthStore $jwtAuthStore
	 */
	public function __construct(
		Config             $mainConfig,
		AuthManager        $authManager,
		UserIdentityLookup $userIdentityLookup,
		JWTAuthStore       $jwtAuthStore
	) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
		$this->userIdentityLookup = $userIdentityLookup;
		$this->jwtAuthStore = $jwtAuthStore;
	}

	/**
	 * @param string $configId
	 * @param array $config
	 * @return void
	 */
	public function init( string $configId, array $config ): void {
		parent::init( $configId, $config );
		$this->migrateUsersByEmail = $this->getConfigValue( 'MigrateUsersByEmail' );
		$this->migrateUsersByUserName = $this->getConfigValue( 'MigrateUsersByUserName' );
		$this->useRealNameAsUserName = $this->getConfigValue( 'UseRealNameAsUserName' );
		$this->useEmailNameAsUserName = $this->getConfigValue( 'UseEmailNameAsUserName' );
		$jwtSettings = JWTAuthSettings::initialize(
			$this->getConfigValue( 'Algorithm' ),
			$this->getConfigValue( 'Key' ),
			$this->getConfigValue( 'RequiredClaims' )
		);
		$this->jwtHandler = new JWTHandler(
			$jwtSettings,
			$this->getLogger()
		);
	}

	/**
	 * @param string $name
	 * @return mixed
	 */
	private function getConfigValue( string $name ) {
		return $this->getData()->has( $name ) ? $this->getData()->get( $name ) :
			$this->mainConfig->get( 'JWTAuth_' . $name );
	}

	/**
	 * @param int|null &$id The user's user ID
	 * @param string|null &$username The user's username
	 * @param string|null &$realname The user's real name
	 * @param string|null &$email The user's email address
	 * @param string|null &$errorMessage Returns a descriptive message if there's an error
	 * @return bool true if the user has been authenticated and false otherwise
	 */
	public function authenticate(
		?int    &$id,
		?string &$username,
		?string &$realname,
		?string &$email,
		?string &$errorMessage
	): bool {
		// Get JWT data from Authorization header or POST data
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$jwtDataRaw = $_SERVER['HTTP_AUTHORIZATION'];
		} elseif ( isset( $_POST[self::JWTAUTH_POST_PARAMETER] ) ) {
			$jwtDataRaw = $_POST[self::JWTAUTH_POST_PARAMETER];
		} else {
			$jwtDataRaw = '';
		}

		// Clean data
		$cleanJWTData = $this->jwtHandler->preprocessRawJWTData( $jwtDataRaw );

		if ( empty( $cleanJWTData ) ) {
			// Invalid, no JWT
			$errorMessage = new Message( 'jwtauth-invalid-jwt' );
			$this->getLogger()->error( $errorMessage );
			return false;
		}

		// Process JWT and get results back
		$jwtResults = $this->jwtHandler->processJWT( $cleanJWTData );

		if ( is_string( $jwtResults ) ) {
			// Invalid results
			$errorMessage = $jwtResults;
			$this->getLogger()->error( "Unable to process JWT. The error message was: $jwtResults" );
			return false;
		}

		$jwtResponse = $jwtResults;
		$realname = $jwtResponse->getFullName();
		$email = $jwtResponse->getEmailAddress();

		$subject = $jwtResponse->getSubject();
		$this->authManager->setAuthenticationSessionData( self::JWTAUTH_SUBJECT_SESSION_KEY, $subject );

		$issuer = $jwtResponse->getIssuer();
		$this->authManager->setAuthenticationSessionData( self::JWTAUTH_ISSUER_SESSION_KEY, $issuer );

		$attributes = $jwtResponse->getAttributes();
		$this->authManager->getRequest()->getSession()->setSecret( self::JWTAUTH_ATTRIBUTES_SESSION_KEY, $attributes );

		$this->getLogger()->debug(
			'Real name: ' . $realname .
			', Email: ' . $email .
			', Subject: ' . $subject .
			', Issuer: ' . $issuer
		);

		list( $id, $username ) = $this->jwtAuthStore->findUser( $subject, $issuer );
		if ( $id !== null ) {
			$this->getLogger()->debug( 'Found user with matching subject and issuer.' . PHP_EOL );
			return true;
		}

		$this->getLogger()->debug( 'No user found with matching subject and issuer.' . PHP_EOL );

		if ( $this->migrateUsersByEmail && ( $email ?? '' ) !== '' ) {
			$this->getLogger()->debug( 'Checking for email migration.' . PHP_EOL );
			list( $id, $username ) = $this->getMigratedIdByEmail( $email );
			if ( $id !== null ) {
				$this->saveExtraAttributes( $id );
				$this->getLogger()->debug( 'Migrated user ' . $username . ' by email: ' . $email . '.' . PHP_EOL );
				return true;
			}
		}

		$preferred_username = $this->getPreferredUsername( $attributes, $realname, $email );
		$this->getLogger()->debug( 'Preferred username: ' . $preferred_username . PHP_EOL );

		if ( $this->migrateUsersByUserName ) {
			$this->getLogger()->debug( 'Checking for username migration.' . PHP_EOL );
			$id = $this->getMigratedIdByUserName( $preferred_username );
			if ( $id !== null ) {
				$this->saveExtraAttributes( $id );
				$this->getLogger()->debug( 'Migrated user by username: ' . $preferred_username . '.' .
					PHP_EOL );
				$username = $preferred_username;
				return true;
			}
		}

		$username = $this->getAvailableUsername( $preferred_username );

		$this->getLogger()->debug( 'Available username: ' . $username . PHP_EOL );

		return true;
	}

	/**
	 * @param UserIdentity &$user
	 */
	public function deauthenticate( UserIdentity &$user ): void {
		// intentionally left blank
	}

	/**
	 * @param UserIdentity $user
	 * @return array
	 */
	public function getAttributes( UserIdentity $user ): array {
		return $this->authManager->getRequest()->getSession()->getSecret( self::JWTAUTH_ATTRIBUTES_SESSION_KEY );
	}

	/**
	 * @param int $id user id
	 */
	public function saveExtraAttributes( int $id ): void {
		$subject = $this->authManager->getAuthenticationSessionData( self::JWTAUTH_SUBJECT_SESSION_KEY );
		$issuer = $this->authManager->getAuthenticationSessionData( self::JWTAUTH_ISSUER_SESSION_KEY );
		$this->jwtAuthStore->saveExtraAttributes( $id, $subject, $issuer );
	}

	private function getPreferredUsername( array $attributes, ?string $realname, ?string $email ): ?string {
		$preferred_username = '';
		$attributeName = 'preferred_username';
		if ( $this->getData()->has( 'preferred_username' ) ) {
			$attributeName = $this->getData()->get( 'preferred_username' );
			$this->getLogger()->debug( 'Using ' . $attributeName . ' attribute for preferred username.' . PHP_EOL );
		}
		if ( isset( $attributes[$attributeName] ) ) {
			$preferred_username = $attributes[$attributeName];
		}

		if ( strlen( $preferred_username ) > 0 ) {
			// do nothing
		} elseif ( $this->useRealNameAsUserName && ( $realname ?? '' ) !== '' ) {
			$preferred_username = $realname;
		} elseif ( $this->useEmailNameAsUserName && ( $email ?? '' ) !== '' ) {
			$pos = strpos( $email, '@' );
			if ( $pos !== false && $pos > 0 ) {
				$preferred_username = substr( $email, 0, $pos );
			} else {
				$preferred_username = $email;
			}
		} else {
			return null;
		}
		$nt = Title::makeTitleSafe( NS_USER, $preferred_username );
		if ( $nt === null ) {
			return null;
		}
		return $nt->getText();
	}

	private function getMigratedIdByUserName( string $username ): ?string {
		$nt = Title::makeTitleSafe( NS_USER, $username );
		if ( $nt === null ) {
			$this->getLogger()->debug( 'Invalid preferred username for migration: ' . $username . '.' . PHP_EOL );
			return null;
		}
		$username = $nt->getText();
		return $this->jwtAuthStore->getMigratedIdByUserName( $username );
	}

	private function getMigratedIdByEmail( string $email ): array {
		$this->getLogger()->debug( 'Matching user to email ' . $email . '.' . PHP_EOL );
		return $this->jwtAuthStore->getMigratedIdByEmail( $email );
	}

	private function getAvailableUsername( ?string $preferred_username ): string {
		if ( $preferred_username === null ) {
			$preferred_username = 'User';
		}

		$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username );
		if ( !$userIdentity || !$userIdentity->isRegistered() ) {
			return $preferred_username;
		}

		$count = 1;
		$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username . $count );
		while ( $userIdentity && $userIdentity->isRegistered() ) {
			$count++;
			$userIdentity = $this->userIdentityLookup->getUserIdentityByName( $preferred_username . $count );
		}
		return $preferred_username . $count;
	}
}
