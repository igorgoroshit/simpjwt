<?php

namespace Igorgoroshit\SimpJWT\Providers;

use Illuminate\Support\ServiceProvider;

use Igorgoroshit\SimpJWT\JWT;
use Igorgoroshit\SimpJWT\Helpers\JSON;
use Igorgoroshit\SimpJWT\Helpers\Base64;


class JWTServiceProvider extends ServiceProvider {
    public function register()
    {
        $this->app['JWT'] = $this->app->share(function($app) {
            return new JWT();
        });
    }
}