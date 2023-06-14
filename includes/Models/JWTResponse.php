<?php

namespace MediaWiki\Extension\JWTAuth\Models;

class JWTResponse {
    private string $externalUserID;
    private string $username;
    private string $firstName;
    private string $lastName;
    private string $emailAddress;
    private string $issuer;
    private string $audience;
    private string $subject;
    private array $attributes;

    private function __construct() {
    }

    public static function buildJWTResponse( JWTAuthSettings $settings ): JWTResponse {
        $jwtResponseObject = new JWTResponse();
        $jwtResponseObject->settings = $settings;
        return $jwtResponseObject;
    }

    public function getUsername(): string {
        // TODO: Add more checks to ensure username fits with MediaWiki requirements
        $username = $this->username;

        if ( !empty( $username ) ) {
            $candidateUsername = $username;
        } elseif ( !empty( $this->getEmailAddress() ) ) {
            $emailAddressComponents = explode( '@', $this->getEmailAddress() );
            $candidateUsername = ucfirst( $emailAddressComponents[0] );
        } else {
            $candidateUsername = ucfirst( $this->getFirstName() ) . $this->getLastName();
        }

        return $candidateUsername;
    }

    public function getEmailAddress(): string {
        return $this->emailAddress ?? '';
    }

    public function getFirstName(): string {
        return $this->firstName ?? '';
    }

    public function getLastName(): string {
        return $this->lastName ?? '';
    }

    public function getFullName(): string {
        return $this->getFirstName() . ' ' . $this->getLastName();
    }

    public function getIssuer(): string {
        return $this->issuer;
    }

    public function getAudience(): string {
        return $this->audience;
    }

    public function getSubject(): string {
        return $this->subject;
    }

    public function getExternalUserID(): string {
        return $this->externalUserID;
    }

    public function getAttributes(): array {
        return $this->attributes;
    }

    public function setUsername( string $username ): JWTResponse {
        $this->username = ucfirst( $username );
        return $this;
    }

    public function setFirstName( string $firstName ): JWTResponse {
        $this->firstName = $firstName;
        return $this;
    }

    public function setLastName( string $lastName ): JWTResponse {
        $this->lastName = $lastName;
        return $this;
    }

    public function setEmailAddress( string $emailAddress ): JWTResponse {
        if ( strpos( $emailAddress, '@' ) === false ) {
            $emailAddress = '';
        }
        $this->emailAddress = $emailAddress;
        return $this;
    }

    public function setIssuer( string $issuer ): JWTResponse {
        $this->issuer = $issuer;
        return $this;
    }

    public function setAudience( string $audience ): JWTResponse {
        $this->audience = $audience;
        return $this;
    }

    public function setSubject( string $subject ): JWTResponse {
        $this->subject = $subject;
        return $this;
    }

    public function setExternalUserID( string $externalUserID ): JWTResponse {
        $this->externalUserID = $externalUserID;
        return $this;
    }

    public function setAttributes( array $attributes ): JWTResponse {
        $this->attributes = $attributes;
        return $this;
    }
}
