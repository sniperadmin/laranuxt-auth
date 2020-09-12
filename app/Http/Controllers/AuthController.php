<?php

namespace App\Http\Controllers;

use App\User;
use Illuminate\Http\Request;
use App\Utilities\ProxyRequest;

class AuthController extends Controller
{
    protected $proxy;

    public function __construct(ProxyRequest $proxy)
    {
        $this->proxy = $proxy;
    }

    /**
     * register method
     * @param name,email,password
     * @return Array[token,expiresIn,message]
     * 
     */
    public function register()
    {
        $this->validate(request(), [
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required',
        ]);
            
        $user = User::create([
            'name' => request('name'),
            'email' => request('email'),
            'password' => bcrypt(request('password'))
        ]);

        $res = $this->proxy->grantPasswordToken(
            $user->email,
            request('password')
        );

        return response([
            'token' => $res->access_token,
            'expiresIn' => $res->expires_in,
            'message' => 'Your account has been created!'
        ], 201);
    }

    /**
     * login method
     * @param email,password
     * @return Array[token,expiresIn,message]
     * 
     */
    public function login()
    {
        $user = User::where('email', request('email'))->first();

        abort_unless($user, 404, 'Credentials do not exists!');
        abort_unless(
            \Hash::check(request('password'), $user->password),
            404,
            'Email or password is not correct!'
        );

        $res = $this->proxy
            ->grantPasswordToken(request('email'), request('password'));

        return response([
            'token' => $res->access_token,
            'expiresIn' => $res->expires_in,
            'message' => 'Logged in!',
        ], 200);
    }

    /**
     * refresh token method
     * @return Array[token,expiresIn,message]
     * 
     */
    public function refreshToken()
    {
        $res = $this->proxy->refreshAccessToken();

        return response([
            'token' => $res->access_token,
            'expiresIn' => $res->expires_in,
            'message' => 'Token Refreshed!',
        ], 200);
    }

    /**
     * refresh token method
     * @return Array[token,expiresIn,message]
     * 
     */
    public function logout()
    {
        $token = request()->user()->token();
        $token->delete();

        // cookie remove
        cookie()->queue(cookie()->forget('refresh_token'));

        return response([
            'message' => 'successfully logged out!'
        ], 200);
    }
}
