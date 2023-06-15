<?php

namespace MediaWiki\Extension\JWTAuth;

class JWTAuthStore {

	/**
	 * @param int $id user id
	 * @param string $subject
	 * @param string $issuer
	 */
	public function saveExtraAttributes( int $id, string $subject, string $issuer ): void {
		$dbw = wfGetDB( DB_PRIMARY );
		$dbw->upsert(
			'jwtauth',
			[
				'jwtauth_user' => $id,
				'jwtauth_subject' => $subject,
				'jwtauth_issuer' => $issuer
			],
			[
				[ 'jwtauth_user' ]
			],
			[
				'jwtauth_subject' => $subject,
				'jwtauth_issuer' => $issuer
			],
			__METHOD__
		);
	}

	/**
	 * @param string $subject
	 * @param string $issuer
	 * @return array
	 */
	public function findUser( string $subject, string $issuer ): array {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'jwtauth'
			],
			[
				'user_id',
				'user_name'
			],
			[
				'jwtauth_subject' => $subject,
				'jwtauth_issuer' => $issuer
			],
			__METHOD__,
			[],
			[
				'jwtauth' => [ 'JOIN', [ 'user_id=jwtauth_user' ] ]
			]
		);
		if ( $row === false ) {
			return [ null, null ];
		} else {
			return [ $row->user_id, $row->user_name ];
		}
	}

	/**
	 * @param string $username
	 * @return string|null
	 */
	public function getMigratedIdByUserName( string $username ): ?string {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'jwtauth'
			],
			[
				'user_id'
			],
			[
				'user_name' => $username
			],
			__METHOD__,
			[],
			[
				'jwtauth' => [ 'LEFT JOIN', [ 'user_id=jwtauth_user' ] ]
			]
		);
		if ( $row !== false ) {
			return $row->user_id;
		}
		return null;
	}

	/**
	 * @param string $email
	 * @return array
	 */
	public function getMigratedIdByEmail( string $email ): array {
		$dbr = wfGetDB( DB_REPLICA );
		$row = $dbr->selectRow(
			[
				'user',
				'jwtauth'
			],
			[
				'user_id',
				'user_name',
				'jwtauth_user'
			],
			[
				'user_email' => $email
			],
			__METHOD__,
			[
				// if multiple matching accounts, use the oldest one
				'ORDER BY' => 'user_registration'
			],
			[
				'jwtauth' => [ 'LEFT JOIN', [ 'user_id=jwtauth_user' ] ]
			]
		);
		if ( $row !== false && $row->jwtauth_user === null ) {
			return [ $row->user_id, $row->user_name ];
		}
		return [ null, null ];
	}
}
