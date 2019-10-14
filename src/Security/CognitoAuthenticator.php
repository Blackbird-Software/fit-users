<?php

declare(strict_types=1);

namespace App\Security;

use App\Bridge\AwsCognitoClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Guard\AbstractGuardAuthenticator;

class CognitoAuthenticator extends AbstractGuardAuthenticator
{
    private $cognitoClient;

    public function __construct(AwsCognitoClient $cognitoClient)
    {
        $this->cognitoClient = $cognitoClient;
    }

    public function checkCredentials($credentials, UserInterface $user)
    {
        try {
            $this->cognitoClient->checkCredentials(
                $credentials['email'],
                $credentials['password']
            );
        } catch (CognitoIdentityProviderException $exception) {
            return false;
        }

        return true;
    }

    public function supports(Request $request)
    {
        // @TODO narrow the context
        return true;
    }

    public function getCredentials(Request $request)
    {
        return [
          'email' => $request->request->get('email'),
          'password' => $request->request->get('password'),
        ];
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        return $userProvider->loadUserByUsername($credentials['email']);
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $data = [
            'message' => strtr($exception->getMessageKey(), $exception->getMessageData()),
        ];

        return new JsonResponse($data, Response::HTTP_FORBIDDEN);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, $providerKey)
    {
        // return key?
        return null;
    }

    public function start(Request $request, ?AuthenticationException $authException = null)
    {
        $data = [
            'message' => 'Authentication Required',
        ];

        return new JsonResponse($data, Response::HTTP_UNAUTHORIZED);
    }

    public function supportsRememberMe()
    {
        return false;
    }
}
