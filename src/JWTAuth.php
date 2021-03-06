<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use App\Models\UserModel;
use Tymon\JWTAuth\Http\Parser\Parser;
use Tymon\JWTAuth\Contracts\Providers\Auth;

class JWTAuth extends JWT
{
    /**
     * @var \Tymon\JWTAuth\Contracts\Providers\Auth
     */
    protected $auth;

    /**
     * @param  \Tymon\JWTAuth\Manager  $manager
     * @param  \Tymon\JWTAuth\Contracts\Providers\Auth  $auth
     * @param  \Tymon\JWTAuth\Http\Parser\Parser  $parser
     *
     * @return void
     */
    public function __construct(Manager $manager, Auth $auth, Parser $parser)
    {
        parent::__construct($manager, $parser);
        $this->auth = $auth;
    }

    /**
     * Attempt to authenticate the user and return the token.
     *
     * @param  array  $credentials
     *
     * @return false|string
     */
    public function attempt(array $credentials)
    {
        if (! $this->auth->byCredentials($credentials)) {
            return false;
        }

        return $this->fromUser($this->user());
    }

/**
     * Authenticate a user via a token.
     *
     * @param mixed $token
     *
     * @return mixed
     */
    public function authenticate($token = false) {
        $device = $this->getPayload($token)->get('device');
        if ($device == 'mobile') {
            $mobile = $this->getPayload($token)->get('mobile');
            $user = UserModel::where('mobile', $mobile)->first();
            if (!$user) {
                return false;
            }
            return $user->mobile;
        } else {
            $email = $this->getPayload($token)->get('email');
            $password = $this->getPayload($token)->get('password');
            $user = UserModel::where('email', $email)->first();
            if (!$user) {
                return false;
            }
            return $user;
        }
    }
    /**
     * Alias for authenticate().
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject|false
     */
    public function toUser()
    {
        return $this->authenticate();
    }

    /**
     * Get the authenticated user.
     *
     * @return \Tymon\JWTAuth\Contracts\JWTSubject
     */
    public function user()
    {
        return $this->auth->user();
    }
}
