<?php
namespace MediaWiki\Extension\JWTAuth;

use Exception;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\SignatureInvalidException;
use MediaWiki\Extension\JWTAuth\Models\JWTAuthSettings;
use MediaWiki\Extension\JWTAuth\Models\JWTResponse;
use MediaWiki\Logger\LoggerFactory;
use Psr\Log\LoggerInterface;
use Wikimedia\Assert\Assert;

class JWTHandler {
    /**
     * @var JWTAuthSettings $jwtSettings The JWT settings object.
     */
    private JWTAuthSettings $jwtSettings;

    /**
     * @var LoggerInterface $logger The logger object.
     */
    private LoggerInterface $logger;

    /**
     * JWTHandler constructor.
     *
     * @param JWTAuthSettings $jwtSettings The JWT settings object.
     * @param LoggerInterface $logger The logger object.
     */
    public function __construct(
        JWTAuthSettings $jwtSettings,
        LoggerInterface $logger
    ) {
        $this->jwtSettings = $jwtSettings;
        $this->logger = $logger;
    }

    /**
     * Preprocesses the raw JWT data.
     *
     * @param string $rawJWTData The raw JWT data to be preprocessed.
     *
     * @return string Returns the preprocessed JWT data.
     */
    public function preprocessRawJWTData(
        string $rawJWTData
    ): string {
        // Checks if the $rawJWTData string starts with the literal strings "Bearer:" or "Bearer ".
        // If it doesn't start with either, it logs an error message and returns an empty string.
        if (strpos($rawJWTData, 'Bearer:') !== 0 && strpos($rawJWTData, 'Bearer ') !== 0) {
            $this->logger->debug("Invalid JWT auth, doesn't start with Bearer");
            return '';
        }
        // Extract the JWT substring after the first 7 characters, which removes the "Bearer:" or "Bearer " prefix.
        // Remove any white space characters from the $rawJWTData string and output as $cleanJWTData.
        $rawJWTData = str_replace(['Bearer:', 'Bearer '], '', $rawJWTData);
        $cleanJWTData = preg_replace('/\s+/', '', $rawJWTData);
    
        return $cleanJWTData;
    }
    
    /**
     * Processes the JWT token and returns a JWTResponse object or an error message.
     *
     * @param string $rawJWT The raw JWT token to be processed.
     *
     * @return JWTResponse|string Returns a JWTResponse object if the token is valid, or an error message if the token is invalid.
     */
    public function processJWT(
        string $rawJWT
    ) {
        $keyObj = $this->getJWTKey();
        $decodedJWT = $this->decodeJWT(
            $rawJWT,
            $keyObj
        );

        if ($decodedJWT !== null &&
            is_array($decodedJWT) &&
            in_array('error', $decodedJWT) &&
            $decodedJWT['error'] === true) {
            if (!empty($decodedJWT['errorMessage'])) {
                $errorMessage = $decodedJWT['errorMessage'];
            }
            return $errorMessage;
        }

        $this->logger->debug(print_r($decodedJWT, true));

        $stagingArea = [];

        foreach (JWTAuth::EXTENSION_REQUIRED_CLAIMS as $claimName) {
            $stagingArea[$claimName] = $decodedJWT[$claimName];
            $this->logger->debug("Claim $claimName: " . $stagingArea[$claimName]);
        }

        foreach (JWTAuth::EXTENSION_OPTIONAL_CLAIMS as $claimName) {
            if (isset($decodedJWT[$claimName])) {
                $stagingArea[$claimName] = $decodedJWT[$claimName];
            } else {
                $stagingArea[$claimName] = '';
            }
            $this->logger->debug("Claim $claimName: " . $stagingArea[$claimName]);
        }

        $jwtResponse = JWTResponse::buildJWTResponse($this->jwtSettings)
                            ->setUsername($stagingArea[JWTAuth::CLAIM_NAMES['username']])
                            ->setEmailAddress($stagingArea[JWTAuth::CLAIM_NAMES['email']])
                            ->setExternalUserID($stagingArea['ID'])
                            ->setFirstName($stagingArea[JWTAuth::CLAIM_NAMES['firstName']])
                            ->setLastName($stagingArea[JWTAuth::CLAIM_NAMES['lastName']])
                            ->setIssuer($stagingArea[JWTAuth::CLAIM_NAMES['issuer']])
                            ->setAudience($stagingArea[JWTAuth::CLAIM_NAMES['audience']])
                            ->setSubject($stagingArea[JWTAuth::CLAIM_NAMES['subject']])
                            ->setGroups($stagingArea[$this->jwtSettings->getGroupsClaimName()]);

        return $jwtResponse;
    }

    /**
     * Gets the JWT key.
     *
     * @return Key Returns the JWT key.
     */
    private function getJWTKey(): Key {
        $jwtAlgorithm = $this->jwtSettings->getAlgorithm();
        $jwtKey = $this->jwtSettings->getKey();

        try {
            $key = new Key(
                $jwtKey,
                $jwtAlgorithm
            );
            return $key;
        } catch (Exception $ex) {
            $errorMessage = $ex->__toString();
            $this->logger->debug($errorMessage . PHP_EOL);
        }
    }

    private function decodeJWT(
        string $jwtString,
        Key $jwtKey
    ): array {
        $this->logger->debug('Entering decodeJWT');
        try {
            $this->logger->debug('Calling JWT library decode function');
            $decodedJWTObj = JWT::decode(
                $jwtString,
                $jwtKey
            );
            $this->logger->debug('Got back result without errors thrown, now converting object to array');
            $decodedJWTDict = (array) $decodedJWTObj;
            $this->logger->debug('Converted to array');

            if (!$this->isDecodedJWTValid($decodedJWTDict)) {
                return [
                    'error' => true,
                    'errorMessage' => 'Invalid JWT after decoding. JWT may be missing required data.'
                ];
            } else {
                return $decodedJWTDict;
            }
        } catch (\Firebase\JWT\InvalidArgumentException $e) {
            // provided key/key-array is empty or malformed.
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT. The JWT key was not valid.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        } catch (\Firebase\JWT\DomainException $e) {
            // provided algorithm is unsupported OR
            // provided key is invalid OR
            // unknown error thrown in openSSL or libsodium OR
            // libsodium is required but not available.
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT. Either the provided algorithm is unsupported, the provided key is invalid, or an issue happened with OpenSSL/libsodium.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        } catch (\Firebase\JWT\SignatureInvalidException $e) {
            // provided JWT signature verification failed.
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT. The JWT signature was not valid.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        } catch (\Firebase\JWT\BeforeValidException $e) {
            // provided JWT is trying to be used before "nbf" claim OR
            // provided JWT is trying to be used before "iat" claim.
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT. This JWT is not yet valid.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        } catch (\Firebase\JWT\ExpiredException $e) {
            // provided JWT is trying to be used after "exp" claim.
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT. This JWT is expired.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        } catch (\Firebase\JWT\UnexpectedValueException $e) {
            // provided JWT is malformed OR
            // provided JWT is missing an algorithm / using an unsupported algorithm OR
            // provided JWT algorithm does not match provided key OR
            // provided key ID in key/key-array is empty or invalid.
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT. The JWT provided is malformed.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        } catch (Exception $ex) {
            $errorMessage = $ex->__toString();
            $this->logger->debug($errorMessage . PHP_EOL);
            $errorMessageToReturn = 'Error occurred while attempting to decode JWT.';

            return [
                'error' => true,
                'errorMessage' => $errorMessageToReturn
            ];
        }
    }

    private function isDecodedJWTValid(
        array $decodedJWT
    ): bool {
        if ($decodedJWT === null) return false;
        if (empty($decodedJWT)) return false;
        if (!is_array($decodedJWT)) return false;

        // Check if all required claims are there
        foreach (JWTAuth::EXTENSION_REQUIRED_CLAIMS as $claimName) {
            if (empty($decodedJWT[$claimName])) {
                $this->logger->debug('JWT is missing always-required claim: ' . $claimName . PHP_EOL);
                return false;
            }
        }
        // Additional claims, if desired
        $requiredClaims = $this->jwtSettings->getRequiredClaims();
        foreach ($requiredClaims as $claimName) {
            if (empty($decodedJWT[$claimName])) {
                $this->logger->debug('JWT is missing site-required claim: ' . $claimName . PHP_EOL);
                return false;
            }
        }

        return true;
    }
}
