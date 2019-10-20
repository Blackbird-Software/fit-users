<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\Security\Core\User\UserInterface;

final class User implements UserInterface
{
    /** @var string */
    private $email;

    /** @var array */
    private $roles = [];

    /**
     * User constructor.
     */
    public function __construct(string $email, ?array $roles = [])
    {
        $this->email = $email;
        $this->roles = $roles ?? ['ROLE_USER'];
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getUsername(): string
    {
        return (string) $this->email;
    }

    /**
     * @see UserInterface
     */
    public function getRoles(): array
    {
        return array_unique($this->roles);
    }

    /**
     * @see UserInterface
     */
    public function getPassword(): void
    {
    }

    /**
     * @see UserInterface
     */
    public function getSalt(): void
    {
    }

    /**
     * @see UserInterface
     */
    public function eraseCredentials(): void
    {
    }
}
