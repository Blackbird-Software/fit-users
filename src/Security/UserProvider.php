<?php

declare(strict_types=1);

namespace App\Security;

use App\Bridge\AwsCognitoClient;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class UserProvider implements UserProviderInterface
{
    /** @var AWSCognitoClient */
    private $cognitoClient;

    public function __construct(AWSCognitoClient $cognitoClient)
    {
        $this->cognitoClient = $cognitoClient;
    }

    /**
     * @param string $username
     *
     * @return User|UserInterface
     */
    public function loadUserByUsername($username): UserInterface
    {
        $result = $this->cognitoClient->findByUsername($username);

        if (!$result) {
            throw new UsernameNotFoundException();
        }

        $groups = $this->cognitoClient->getRolesForUsername($username);
        $roles = [];

        if (count($groups['Groups']) > 0) {
            $roles = array_map(function ($item) {
                return 'ROLE_'.$item['GroupName'];
            }, $groups['Groups']);
        }

        return new User($username, $roles);
    }

    /**
     * @return User|UserInterface
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Invalid user class "%s".', get_class($user)));
        }

        return $this->loadUserByUsername($user->getEmail());
    }

    /**
     * @param string $class
     */
    public function supportsClass($class): bool
    {
        return $class === User::class;
    }
}
