<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'phone' => 'required|string|unique:users,phone',
            'password' => 'required|string|min:6',
        ]);


        $user = User::create([
            'name' => $request->name,
            'phone' => $request->phone,
            'password' => bcrypt($request->password),
            // 'verification_code' => $verificationCode,
        ]);

        $verificationCode = mt_rand(100000, 999999);
        DB::table('users')->where('id', $user->id)->update(['verification_code' => $verificationCode]);
        $user->refresh();

        \Log::info("verification_code for"  . $user->phone . ':'  . $user->verification_code);

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            "user" => [
                'id' => $user->id,
                'name' => $user->name,
                'phone' => $user->phone,
                'verification_code' => $user->verification_code,
            ],
            "token" => $token
        ]);
    }

    public function login(Request $request)
    {
        $request->validate([
            'phone' => 'required|string',
            'password' => 'required|string',
        ]);

        $user = User::where('phone', $request->phone)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }
        if (!$user->is_verified) {
            return response()->json(['message' => 'Account not verified'], 401);
        }

        $token = $user->createToken('auth_token')->plainTextToken;

        return response()->json([
            "user" => [
                'id' => $user->id,
                'name' => $user->name,
                'phone' => $user->phone,
                'is_verified' => $user->is_verified,
            ],
            "token" => $token
        ]);
    }

    public function verifyCode(Request $request)
    {
        $request->validate([
            'phone' => 'required|string',
            'verification_code' => 'required|string',
        ]);

        $user = User::where('phone', $request->phone)
            ->where('verification_code', $request->verification_code)
            ->first();

        if (!$user) {
            return response()->json(['message' => 'Verification failed'], 400);
        }
        $user->is_verified = true;
        // $user->verification_code = null;
        $user->save();

        return response()->json(['message' => 'Account verified successfully'], 200);
    }
}
