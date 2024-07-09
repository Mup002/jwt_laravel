<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Facades\JWTAuth;
class AuthController extends Controller
{
    //
    public function __construct()
    {
        $this->middleware('auth:api',['except'=> ['login','refresh']]);
    }
    public function login()
    {
        $credentials = request(['email','password']);

        if (! $token = auth() -> attempt($credentials)) {
            return response() -> json(['error' => 'Unauthorized'],401);
        }

        $refreshToken = $this->createRefreshToken();

        return $this->responseWithToken($token,$refreshToken);
    }

    public function refresh(){
        $refreshToken = request()->refresh_token;
        try{
            $decoded = JWTAuth::getJWTProvider()->decode($refreshToken);
            $user= User::find($decoded['user_id']);
            if(!$user){
                return response()->json(['error'=>'user not found'],404);
            }
            auth()->invalidate();
            $token = auth()->login($user);
            $refreshToken = $this->createRefreshToken();
            return $this->responseWithToken($token,$refreshToken);
        }catch(JWTException $e){
            return response()->json(['error' => 'Refresh token invalid'],500);
        }

    }
    protected function createRefreshToken(){

        $data = [
            'user_id' => auth()->user()->id,
            'random' => rand() . time(),
            'exp' => time() + config('jwt.refresh_ttl')
        ];
        $refreshToken = JWTAuth::getJWTProvider()->encode($data);
        return $refreshToken;
    }
    protected function responseWithToken($token,$refreshToken)
    {
        return response() -> json([
            'access_token' => $token,
            'refresh_token' => $refreshToken,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
        ]);
    }

    public function profile(){
        return response()->json(auth()->user());
    }
    public function logout(){
        auth()->logout();
        return response()->json(['message'=>'Successfully logged out']);
    }
}
