<?php

namespace MikeMcLin\Passport;

use Laravel\Passport\Bridge\RefreshTokenRepository;
use Laravel\Passport\Bridge\UserRepository;
use Laravel\Passport\Passport;
use Laravel\Passport\PassportServiceProvider;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\Grant\PasswordGrant;

/**
 * Class CustomQueueServiceProvider
 *
 * @package App\Providers
 */
class CustomRequestGrantProvider extends PassportServiceProvider
{
    // /**
    //  * Bootstrap any application services.
    //  *
    //  * @return void
    //  */
    // public function boot()
    // {
    //     $server = app(AuthorizationServer::class);
    //     $server->setEncryptionKey(env('APP_ENV'));
    //     $server->enableGrantType(
    //         $this->makeCustomRequestGrant(),
    //         Passport::tokensExpireIn()
    //     );
    // }

    /**
     * Register the service provider.
     *
     * @return void
     */
    public function register()
    {
    }

    /**
     * Register the authorization server.
     *
     * @return void
     */
    protected function registerAuthorizationServer()
    {
        $this->app->singleton(AuthorizationServer::class, function () {
            return tap($this->makeAuthorizationServer(), function ($server) {
                
                $server->enableGrantType(
                    $this->makeCustomRequestGrant(), Passport::tokensExpireIn()
                );
                
                $server->enableGrantType(
                    $this->makeAuthCodeGrant(), Passport::tokensExpireIn()
                );

                $server->enableGrantType(
                    $this->makeRefreshTokenGrant(), Passport::tokensExpireIn()
                );

                $server->enableGrantType(
                    $this->makePasswordGrant(), Passport::tokensExpireIn()
                );

                $server->enableGrantType(
                    new PersonalAccessGrant, new DateInterval('P1Y')
                );

                $server->enableGrantType(
                    new ClientCredentialsGrant, Passport::tokensExpireIn()
                );

                if (Passport::$implicitGrantEnabled) {
                    $server->enableGrantType(
                        $this->makeImplicitGrant(), Passport::tokensExpireIn()
                    );
                }
            });
        });
    }


    /**
     * Create and configure a Password grant instance.
     *
     * @return PasswordGrant
     */
    protected function makeCustomRequestGrant()
    {
        $grant = new CustomRequestGrant(
            $this->app->make(UserRepository::class),
            $this->app->make(RefreshTokenRepository::class)
        );

        $grant->setRefreshTokenTTL(Passport::refreshTokensExpireIn());

        return $grant;
    }
}
