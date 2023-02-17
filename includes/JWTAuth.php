<?php
namespace MediaWiki\Extension\JWTAuth;

class JWTAuth {
    const JWT_AUTH_EXTENSION_NAME = 'JWTAuth';

    const JWT_SUPPORTED_ALGORITHMS = [
        'HS256',
        'RS256',
        'EdDSA'
    ];

    // JWT claims: https://www.iana.org/assignments/jwt/jwt.xhtml

    const CLAIM_NAMES = [
        'username' => 'preferred_username',
        'email' => 'email',
        'firstName' => 'given_name',
        'lastName' => 'family_name',
        'issuer' => 'iss',
        'audience' => 'aud',
        'subject' => 'sub',
        'groups' => 'groups'
    ];

    const LIBRARY_REQUIRED_CLAIMS = [
        'exp',
        'iat',
        'nbf'
    ];

    const EXTENSION_REQUIRED_CLAIMS = [
        'preferred_username',
        'iss',
        'aud',
        'sub'
    ];

    const EXTENSION_OPTIONAL_CLAIMS = [
        'email',
        'ID',
        'given_name',
        'family_name',
        'groups'
    ];
}