<?php

namespace MediaWiki\Extension\JWTAuth;

use DatabaseUpdater;
use MediaWiki\Installer\Hook\LoadExtensionSchemaUpdatesHook;

class SchemaHooks implements LoadExtensionSchemaUpdatesHook {
	/**
	 * Updates database schema.
	 *
	 * @param DatabaseUpdater $updater database updater
	 */
	public function onLoadExtensionSchemaUpdates( $updater ) {
		$dir = __DIR__ . '/../sql/' . $updater->getDB()->getType() . '/';
		$updater->addExtensionTable( 'jwtauth', $dir . 'JWTAuth.sql' );
	}
}
