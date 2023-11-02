# GoAuth Service

## Description
GoAuth is an OAuth service implemented with gRPC endpoints, allowing users to register, log in, and consent to clients accessing their data. On the client side, it supports functionalities like registering clients and exchanging/refreshing tokens.

This project aims to provide a robust authentication system using session IDs and JWT for authentication. It includes unit tests and integration tests, which are run using Docker.

## Usage
you can use the gRPC endpoints to interact with the OAuth service. The following functionalities are available:

    - User registration and login, consent
    - Client registration
    - Token exchange and refresh
