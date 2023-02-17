# JWTAuth
Adds support for using JSON Web Tokens to log in to MediaWiki.

## Dependencies
The following requirements need to be met before installing JWTAuth:

- A wiki running MediaWiki 1.35 or above
- Ability to use Composer, to install our dependencies
- A JWT provider that can generate requests to meet standards outlined in the Integration section and uses one of the supported algorithms. (If you do not have enough prior context about how JWTs work, please go to https://jwt.io to learn more.)

## Installation
First and foremost, you need to meet the above dependency requirements.

Add the following to LocalSettings.php, being sure to fill in the proper values where needed:

```php
wfLoadExtension( 'JWTAuth' );
$wgJWTAuthAlgorithm = ''; // can be: HS256, RS256, EdDSA
$wgJWTAuthKey = ''; // Depends on which algorithm you are using
$wgJWTGroupMapping = [
  // one group can map to multiple MediaWiki groups...
  'customgroup1' => [
    'sysop', 'bureaucrat'
  ],
  // ...or just one MediaWiki group.
  'customgroup2' => 'sysop'
];
```

If you need to debug the JWT being sent, turn on debugging by adding `$wgJWTAuthDebugMode = true;` to your LocalSettings.php.

Go to the extension's folder (probably under `extensions/JWTAuth`) and run `composer update --no-dev` to install JWTAuth's dependencies.

## Integration
The following procedure must be followed to successfully authenticate a user into the wiki:

1. A JWT claim must be well formed and encoded into the JWT payload format using the key that has already been agreed upon.
2. Find the path to your wiki's location of `Special:JWTLogin`. For instance, if your wiki is under `https://wiki.example.com` and `$wgArticlePath = "/wiki/$1";` then the location is `https://wiki.example.com/wiki/Special:JWTLogin`.
3. The payload must be `POST`ed to this aforementioned URL. The URL should have a parameter called `Authorization` with the content `Bearer: JWTTOKENHERE`. For instance, `Bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjJ9.0sw4vF5BGhhnv2BMfrxQuNMgFU3mxZpVPsOfkvPWgjs`.
4. The payload must conform to the claim names promulgated by IANA: https://www.iana.org/assignments/jwt/jwt.xhtml

Below are the claims that are required by the JWTAuth extension. If any of these are missing, the authentication process will fail. If you are unsure of what these mean, or the allowed values for them, please visit https://jwt.io for more details.

- `preferred_username`: Username. This is used by JWTAuth to form the user's username on MediaWiki. Please make sure the usernames conform to MediaWiki's allowed username rules.
- `exp`: Expiry timestamp.
- `iat`: Issued at timestamp.
- `nbf`: Not valid before timestamp.
- `iss`: Issuer
- `aud`: Audience
- `sub`: Subject

You can put nonsense (but nonempty) values for `iss`, `aud`, and `sub`, as they are not checked by JWTAuth, but our JWT decoding library (Firebase JWT) may complain if they are not set.

The following claims are optional, but are highly recommended because they will be added to users' profiles:

- `email`
- `family_name`
- `given_name`

These claim names cannot be changed to match the token generator's preferences because these claim names are standard conventions. The party generating the token is responsible for sending well-formed responses that conform to internet standards.

If you want to assign groups to a user, pass them in, separated by commas, by using the `groups` claim. For instance, `"groups": "customgroup1,customgroup2"`. Then, define the mapping in `$wgJWTGroupMapping` like it was done in the example config shown above.

### Testing out JWTAuth using a simple HTML form

If you want to try testing out JWTAuth using a simple form, put the following HTML somewhere and use it to POST the JWT to your wiki. Be sure to replace `PATH_TO_WIKI` with the URL to your wiki.

```html
<form method="post" action="https://PATH_TO_WIKI/wiki/Special:JWTLogin">
  <input type="text" name="Authorization" value="Bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYSIsImF1ZCI6Im5hIiwiaXNzIjoibmEiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJKb2huIERvZSIsImlhdCI6MTUxNjIzOTAyMiwibmJmIjoxNTE2MjM5MDIyLCJleHAiOjE3MTYyMzkwODJ9.gQbzrsJAVtEFjh-a4RwqZtSJ-IHxVvl2cj66VkfljrY">
  <input type="submit">
</form>
```
