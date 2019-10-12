<?php

namespace App\Controller;

use App\Bridge\AwsCognitoClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class UserController extends AbstractController
{
    private $client;

    public function __construct(AwsCognitoClient $awsCognitoClient)
    {
        $this->client = $awsCognitoClient;
    }

    public function register(Request $request): JsonResponse
    {
        $email = $request->request->get('email');
        $password = $request->request->get('password');
        $firstname = $request->request->get('firstname');

        $response = $this->client->register($email, $password, $firstname);

        return new JsonResponse(
            $response->toArray(),
            Response::HTTP_CREATED
        );
    }
}