<?php

namespace Igorgoroshit\JWT\Providers;

use Illuminate\Support\ServiceProvider;
use Igorgoroshit\JWT\Helpers\JSON;
use Igorgoroshit\JWT\Helpers\URLSafeBase64;
use Igorgoroshit\JWT\JWT;

class JWTServiceProvider extends ServiceProvider {
    public function register()
    {
        $this->app['JWT'] = $this->app->share(function($app) {
            return new JWT();
        });
    }
}