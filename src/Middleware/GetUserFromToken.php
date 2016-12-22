<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Middleware;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class GetUserFromToken extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        $token = $request->header('Authorization');
        if (! $token){
            return response()->json(['status'=>'error','error'=>['message'=>'token not provided']],401);
        }

        try {
            $user = $this->auth->authenticate($token);
        } catch (TokenExpiredException $e) {
            return response()->json(['status'=>'error','error'=>['message'=>'token expired']],401);
            //return $this->respond('tymon.jwt.expired', 'token_expired', $e->getStatusCode(), [$e]);
        } catch (JWTException $e) {
            return response()->json(['status'=>'error','error'=>['message'=>'Invalid token']],401);
            //return $this->respond('tymon.jwt.invalid', 'token_invalid', $e->getStatusCode(), [$e]);
        }

        if (! $user) {
            return response()->json(['status'=>'error','error'=>['message'=>'Unauthorised']],401);
        }

        $this->events->fire('tymon.jwt.valid', $user);

        return $next($request);
    }
}
