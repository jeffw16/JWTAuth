<?php
namespace MediaWiki\Extension\JWTAuth;

use MediaWiki\Permissions\Hook\TitleReadWhitelistHook;
use MediaWiki\SpecialPage\SpecialPageFactory;

class Hooks implements TitleReadWhitelistHook {
	private SpecialPageFactory $specialPageFactory;

	public function __construct(SpecialPageFactory $factory) {
		$this->specialPageFactory = $factory;
	}

	/**
	 * Hook to make Special:JWTLogin always be public
	 * Important note: This function's name has not been changed from its original name.
	 * 		   As soon as the name is changed to onTitleReadAllowlist, we will
	 *                 make the corresponding change too.
	 *
	 * @param Title $title
	 * @param User $user User (before login)
	 * @param bool &$allowlisted
	 */
	public function onTitleReadWhitelist($title, $user, &$allowlisted) {
		if ($title->getNamespace() === NS_SPECIAL) {
			[$name, ] = $this->specialPageFactory->resolveAlias($title->getDBKey());
			if ($name === 'JWTLogin') {
				$allowlisted = true;
			}
		}
	}
}
