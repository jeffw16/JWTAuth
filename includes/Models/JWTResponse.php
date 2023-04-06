<?php
namespace MediaWiki\Extension\JWTAuth\Models;

class JWTResponse {
    private JWTAuthSettings $settings;

    private string $externalUserID;
    private string $username;
    private string $firstName;
    private string $lastName;
    private string $emailAddress;
    private string $issuer;
    private string $audience;
    private string $subject;
    private array $groups;
    private array $groupsToRemove;

    private function __construct() {}

    public static function buildJWTResponse(JWTAuthSettings $settings): JWTResponse {
        $jwtResponseObject = new JWTResponse();
        $jwtResponseObject->settings = $settings;
        return $jwtResponseObject;
    }

    public function getUsername(): string {
        // TODO: Add more checks to ensure username fits with MediaWiki requirements
        $username = $this->username;

        if (!empty($username)) {
            $candidateUsername = $username;
        } elseif (!empty($this->getEmailAddress())) {
            $emailAddressComponents = explode('@', $this->getEmailAddress());
            $candidateUsername = ucfirst($emailAddressComponents[0]);
        } else {
            $candidateUsername = ucfirst($firstName) . $lastName;
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

    public function getGroups(): array {
        return $this->groups;
    }

    public function getGroupsToRemove(): array {
        return $this->groupsToRemove;
    }

    public function setUsername(string $username): JWTResponse {
        $this->username = ucfirst($username);
        return $this;
    }

    public function setFirstName(string $firstName): JWTResponse {
        $this->firstName = $firstName;
        return $this;
    }

    public function setLastName(string $lastName): JWTResponse {
        $this->lastName = $lastName;
        return $this;
    }

    public function setEmailAddress(string $emailAddress): JWTResponse {
        if (strpos($emailAddress, '@') === false) {
            $emailAddress = '';
        }
        $this->emailAddress = $emailAddress;
        return $this;
    }

    public function setIssuer(string $issuer): JWTResponse {
        $this->issuer = $issuer;
        return $this;
    }

    public function setAudience(string $audience): JWTResponse {
        $this->audience = $audience;
        return $this;
    }

    public function setSubject(string $subject): JWTResponse {
        $this->subject = $subject;
        return $this;
    }

    public function setExternalUserID(string $externalUserID): JWTResponse {
        $this->externalUserID = $externalUserID;
        return $this;
    }

    public function setGroups(string $commaSeparatedGroups): JWTResponse {
        if (empty($commaSeparatedGroups)) {
            $commaSeparatedGroups = '';
        }

        $groupMapping = $this->settings->getGroupMapping();
        $groupTargets = array_values($groupMapping);
        $allGroups = [];
        // Traverse each of the group targets to get all possible MediaWiki groups that could be assigned
        foreach ($groupTargets as $target) {
            if (is_string($target)) {
                $allGroups = [...$allGroups, $target];
            } elseif (is_array($target)) {
                $allGroups = [...$allGroups, ...$target];
            }
        }
        $allGroups = array_unique($allGroups);

        $groupsArray = explode(',', $commaSeparatedGroups);
        $this->groups = [];

        // For each of the groups passed in for this user from the source
        foreach ($groupsArray as $rawGroupName) {
            // See if the source group is mapped to a wiki group
            $possibleMapping = $groupMapping[$rawGroupName] ?? null;
            // Check if mappings exist
            if (!empty($possibleMapping)) {
                // If string, convert into array
                if (is_string($possibleMapping)) {
                    $possibleMapping = [$possibleMapping];
                }
                // If not array, skip
                if (!is_array($possibleMapping)) {
                    continue;
                }
                // Add all wiki groups it comes with
                $this->groups = [...$this->groups, ...$possibleMapping];
            }
        }
	    $this->groupsToRemove = array_diff($allGroups, $this->groups);

        return $this;
    }
}
