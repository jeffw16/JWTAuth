<?php

namespace MediaWiki\Extension\JWTAuth;

use MediaWiki\Permissions\Hook\TitleReadWhitelistHook;
use MediaWiki\SpecialPage\SpecialPageFactory;


class Hooks implements TitleReadWhitelistHook {

	private SpecialPageFactory $specialPageFactory;

	public function __construct( SpecialPageFactory $factory ) {
		$this->specialPageFactory = $factory;
	}

	/**
	 * Hook to make Special:JWTLogin always be public
	 *
	 * @param Title $title
	 * @param User $user User (before login)
	 * @param bool &$whitelisted
	 */
	public function onTitleReadWhitelist( $title, $user, &$whitelisted ) {
		if ( $title->getNamespace() === NS_SPECIAL ) {
			[ $name, ] = $this->specialPageFactory->resolveAlias( $title->getDBKey() );
			if ( $name === 'JWTLogin' ) {
				$whitelisted = true;
			}
		}
	}
}
