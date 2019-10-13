<?php

namespace App\Bridge;

use Aws\CognitoIdentity\CognitoIdentityProvider;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result;

class AwsCognitoClient
{
    private $client;

    private $poolId;

    private $clientId;

    private $clientSecret;

    public function __construct(
        string $poolId,
        string $clientId,
        string $clientSecret,
        string $key,
        string $secret,
        string $region = 'us-east-1',
        string $version = 'latest'
    )
    {
        $this->client = new CognitoIdentityProviderClient([
            'region' => $region,
            'version' => $version,
            'credentials' => [
                'key' => $key,
                'secret' => $secret
            ]
        ]);
        $this->poolId = $poolId;
        $this->clientId = $clientId;
        $this->clientSecret = $clientSecret;
    }

    public function findByUsername(string $username): ?Result
    {
        try {
            $user = $this->client->adminGetUser([
                'Username' => $username,
                'UserPoolId' => $this->poolId,
            ]);
        } catch (CognitoIdentityProviderException $e) {
            return null;
        }

        return $user;
    }

    public function checkCredentials($username, $password): Result
    {
        return $this->client->adminInitiateAuth([
            'UserPoolId' => $this->poolId,
            'ClientId' => $this->clientId,
            'AuthFlow' => 'ADMIN_NO_SRP_AUTH', // this matches the 'server-based sign-in' checkbox setting from earlier
            'AuthParameters' => [
                'USERNAME' => $username,
                'PASSWORD' => $password,
                'SECRET_HASH' => $this->cognitoSecretHash($username)
            ]
        ]);
    }

    public function getRolesForUsername(string $username): Result
    {
        return $this->client->adminListGroupsForUser([
            'UserPoolId' => $this->poolId,
            'Username' => $username
        ]);
    }

    public function register(string $email, string $password, string $firstname): Result
    {
        $result = $this->client->signUp([
            'UserPoolId' => $this->poolId,
            'ClientId' => $this->clientId,
            'SecretHash' => $this->cognitoSecretHash($email),
            'Password' => $password,
            'Username' => $email,
            'UserAttributes' => [
                [
                    'Name' => 'given_name',
                    'Value' => $firstname
                ]
            ]
        ]);

        return $result;
    }

    protected function cognitoSecretHash(string $username): string
    {
        return $this->hash($username . $this->clientId);
    }

    protected function hash(string $message): string
    {
        $hash = hash_hmac(
            'sha256',
            $message,
            $this->clientSecret,
            true
        );

        return base64_encode($hash);
    }
}