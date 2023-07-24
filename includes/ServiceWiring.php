<?php

namespace MediaWiki\Extension\JWTAuth;

use MediaWiki\MediaWikiServices;

return [
	'JWTAuthStore' =>
		static function ( MediaWikiServices $services ): JWTAuthStore {
			return new JWTAuthStore();
		},
];
