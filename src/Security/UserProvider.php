<?php
namespace App\Security;

use App\Bridge\AwsCognitoClient;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class UserProvider implements UserProviderInterface
{
    /**
     * @var AWSCognitoClient
     */
    private $cognitoClient;

    public function __construct(AWSCognitoClient $cognitoClient)
    {
        $this->cognitoClient = $cognitoClient;
    }

    /**
     * @param string $username
     * @return User|UserInterface
     */
    public function loadUserByUsername($username): UserInterface
    {
        $result = $this->cognitoClient->findByUsername($username);

        if (!$result) {
            throw new UsernameNotFoundException();
        }

        $user = new User();
        $user->setEmail($username);

        $groups = $this->cognitoClient->getRolesForUsername($username);

        if (count($groups['Groups']) > 0) {
            $user->setRoles(
                array_map(
                    function ($item) {
                        return 'ROLE_' . $item['GroupName'];
                    },
                    $groups['Groups']
                )
            );
        }

        return $user;
    }

    /**
     * @param UserInterface $user
     * @return User|UserInterface
     */
    public function refreshUser(UserInterface $user): UserInterface
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(
                sprintf(
                    'Invalid user class "%s".',
                    get_class($user)
                )
            );
        }

        return $this->loadUserByUsername($user->getEmail());
    }

    /**
     * @param string $class
     * @return bool
     */
    public function supportsClass($class): bool
    {
        return User::class === $class;
    }
}
