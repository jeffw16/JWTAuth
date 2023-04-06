<?php
namespace MediaWiki\Extension\JWTAuth;

use Config;
use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use MediaWiki\Extension\JWTAuth\JWTAuth;
use MediaWiki\Extension\JWTAuth\JWTHandler;
use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use MediaWiki\Extension\JWTAuth\Models\ProposedUser;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\SessionManager;
use MediaWiki\User\UserIdentity;
use MediaWiki\User\UserGroupManager;
use Psr\Log\LoggerInterface;
use SpecialPage;
use Title;
use UnlistedSpecialPage;
use User;
use Wikimedia\Assert\Assert;
use Wikimedia\Timestamp\ConvertibleTimestamp;

class JWTLogin extends UnlistedSpecialPage {

    const JWT_EXTENSION = 'JWTAuth';
    const JWT_LOGIN_SPECIAL_PAGE = 'JWTLogin';
    const JWT_PARAMETER = 'Authorization';

    const DEBUG_JWT_PARAMETER = 'debugJWT';
    const RETURN_TO_PAGE_PARAMETER = 'returnToPage';
    const RETURN_TO_PAGE_DEFAULT_VALUE = 'Main_Page';

    private JWTHandler $jwtHandler;
    private $mwConfig;
    private UserGroupManager $userGroupManager;
    private LoggerInterface $logger;

    private $debugMode;

    public function __construct() {
        parent::__construct(self::JWT_LOGIN_SPECIAL_PAGE);

        $mwServicesInstance = MediaWikiServices::getInstance();

        $this->mwConfig = $mwServicesInstance
            ->getConfigFactory()
            ->makeConfig(
                JWTAuth::JWT_AUTH_EXTENSION_NAME
            );
        $this->userGroupManager = $mwServicesInstance->getUserGroupManager();
        $this->logger = LoggerFactory::getInstance(JWTAuth::JWT_AUTH_EXTENSION_NAME);

        $jwtSettings = JWTAuthSettings::initialize(
            $this->mwConfig->get('JWTAuthAlgorithm'),
            $this->mwConfig->get('JWTAuthKey'),
            $this->mwConfig->get('JWTRequiredClaims'),
            $this->mwConfig->get('JWTGroupMapping')
        );

        $this->jwtHandler = new JWTHandler(
            $jwtSettings,
            $this->logger);

        $this->debugMode = $this->mwConfig->get('JWTAuthDebugMode');
    }

    public function execute($subpage) {
        // No errors yet
        $error = '';
    
        // First, need to get the WebRequest from the WebContext
        $request = $this->getContext()->getRequest();
    
        // Get JWT data from Authorization header or POST data
        $jwtDataRaw = '';
        if (isset($_SERVER['HTTP_AUTHORIZATION']) && strpos($_SERVER['HTTP_AUTHORIZATION'], 'Bearer ') === 0) {
            // Authorization header is present and contains a JWT
            $jwtDataRaw = substr($_SERVER['HTTP_AUTHORIZATION'], 7);
        } else {
            // Authorization header is not present, try to get JWT from POST data
            $jwtDataRaw = isset($_POST[self::JWT_PARAMETER]) ? $_POST[self::JWT_PARAMETER] : '';
        }
    
        // Clean data
        $cleanJWTData = $this->jwtHandler->preprocessRawJWTData($jwtDataRaw);
    
        if (empty($cleanJWTData)) {
            // Invalid, no JWT
            return;
        }
    
        // Process JWT and get results back
        $jwtResults = $this->jwtHandler->processJWT($cleanJWTData);
    
        if (is_string($jwtResults)) {
            // Invalid results
            $this->logger->debug("Unable to process JWT. The error message was: $jwtResults");
            $error = $jwtResults;
        } else {
            $jwtResponse = $jwtResults;
        }
        
        if (empty($error)) {
            $proposedUser = ProposedUser::makeUserFromJWTResponse(
                $jwtResponse,
                $this->userGroupManager,
                $this->logger
            );

            $globalSession = $this->getRequest()->getSession();
            $proposedUser->setUserInSession($globalSession);
        }

        if ($this->debugMode === true) {
            $out = $this->getOutput();
            $out->enableOOUI();
            $out->addHTML("<pre>$cleanJWTData</pre><p>" . print_r($jwtResults, true) . "</p><p>Errors, if any:</p><pre>$error</pre>");
        } elseif (!empty($error)) {
            $out = $this->getOutput();
            $out->enableOOUI();
            $out->addHTML(new \OOUI\MessageWidget([
                'type' => 'error',
                'label' => "Sorry, we couldn't log you in at this time. Please inform the site administrators of the following error: $error",
            ]));
        } else {
            $requestedReturnToPage = $this->getRequestParameter(self::RETURN_TO_PAGE_PARAMETER);

            if ($requestedReturnToPage !== null) {
                $this->logger->debug("Return to page: $requestedReturnToPage");
                $returnToUrl = Title::newFromText($requestedReturnToPage)->getFullURL();
            }
            if ($returnToUrl === null || strlen($returnToUrl) === 0) {
                $returnToUrl = Title::newFromText(self::RETURN_TO_PAGE_DEFAULT_VALUE)->getFullURL();
            }
            $this->getOutput()->redirect($returnToUrl);
        }
    }

    private function getRequestParameter($parameterName) {
        return
            (
                in_array($parameterName, $_REQUEST) &&
                !empty($_REQUEST[$parameterName]) &&
                strlen($_REQUEST[$parameterName])
            )
            ? $_REQUEST[$parameterName]
            : null;
    }
}