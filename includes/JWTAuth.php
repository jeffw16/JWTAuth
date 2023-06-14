<?php
namespace MediaWiki\Extension\JWTAuth;

use Config;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use MediaWiki\Extension\PluggableAuth\PluggableAuth;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserRigorOptions;
use Message;

class JWTAuth extends PluggableAuth {
	const JWTAUTH_POST_PARAMETER = 'Authorization';
	const JWTAUTH_ATTRIBUTES_SESSION_KEY = 'Attributes';

	private Config $mainConfig;
	private AuthManager $authManager;
	private UserFactory $userFactory;
	private JWTHandler $jwtHandler;

	/**
	 * @param Config $mainConfig
	 * @param AuthManager $authManager
	 * @param UserFactory $userFactory
	 */
	public function __construct( Config $mainConfig, AuthManager $authManager, UserFactory $userFactory ) {
		$this->mainConfig = $mainConfig;
		$this->authManager = $authManager;
		$this->userFactory = $userFactory;
	}

	/**
	 * @param string $configId
	 * @param array $config
	 * @return void
	 */
	public function init( string $configId, array $config ): void {
		parent::init( $configId, $config );
		$jwtSettings = JWTAuthSettings::initialize(
			$this->getConfigValue( 'AuthAlgorithm' ),
			$this->getConfigValue( 'AuthKey' ),
			$this->getConfigValue( 'RequiredClaims' ),
			$this->getConfigValue( 'GroupMapping' ),
			$this->getConfigValue( 'GroupsClaimName' )
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
			$this->mainConfig->get( 'JWT' . $name );
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
		$username = $jwtResponse->getUsername();
		$realname = $jwtResponse->getFullName();
		$email = $jwtResponse->getEmailAddress();

		$proposedUser = $this->userFactory->newFromName( $username, UserRigorOptions::RIGOR_USABLE );
		if ( $proposedUser === null ) {
			$errorMessage = new Message( 'jwtauth-invalid-username' );
			$this->getLogger()->error( 'Invalid username.' );
			return false;
		}

		$id = $proposedUser->getId();

		$this->setSessionSecret( self::JWTAUTH_ATTRIBUTES_SESSION_KEY, $jwtResponse->getAttributes() );

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
		return $this->getSessionSecret( self::JWTAUTH_ATTRIBUTES_SESSION_KEY );
	}

	/**
	 * @param int $id user id
	 */
	public function saveExtraAttributes( int $id ): void {
		// intentionally left blank
	}

	private function setSessionSecret( $key, $value ) {
		$this->authManager->getRequest()->getSession()->setSecret( $key, $value );
	}

	private function getSessionSecret( $key ) {
		return $this->authManager->getRequest()->getSession()->getSecret( $key );
	}
}
