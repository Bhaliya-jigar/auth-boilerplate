<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use App\Traits\ApiResponser;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;
use App\Http\Resources\UserResource;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Support\Facades\Password;

class AuthenticationController extends Controller
{

    use ApiResponser;

    /**
     * @OA\Post(
     * path="/api/auth/signup",
     * operationId="Register",
     * tags={"Auth"},
     * summary="User Register",
     * description="User Register here",
     *
     *      @OA\RequestBody(
     *         required=true,
     *         description="Pass User Information",
     *         @OA\JsonContent(
     *            required={"email","password"},
     *            @OA\Property(property="name", type="string", format="name", example="John Doe"),
     *            @OA\Property(property="email", type="string", format="email", example="john@mail.com"),
     *            @OA\Property(property="password", type="string", format="password", example="PassWord12345"),
     *         ),
     *      ),
     *
     *      @OA\Response(
     *          response=200,
     *          description="Register Successfully",
     *          @OA\JsonContent(
     *               @OA\Property(property="status", type="boolean", example="true"),
     *               @OA\Property(property="message", type="string", example="User signed up in successfully"),
     *               @OA\Property(
     *                   property="data",
     *                   type="object",
     *                   @OA\Property(property="user", type="object",
     *                          @OA\Property(property="id", type="integer", example="1"),
     *                          @OA\Property(property="name", type="string", example="John Doe"),
     *                          @OA\Property(property="email", type="string", example="John@mail.com"),
     *                          @OA\Property(property="auth_token", type="string", example="3|Wl90TsY0rCGPkkLNllgKDJ0bBBh9Y8fyimN0jl1M")
     *                  ),
     *              ),
     *          )
     *       ),
     *
     *      @OA\Response(response=422,description="Unprocessable Entity"),
     *
     *      @OA\Response(
     *          response=400,
     *          description="Bad request",
     *          @OA\JsonContent(
     *               @OA\Property(property="status", type="boolean", example="false"),
     *               @OA\Property(property="message", type="string", example="validation failed"),
     *               @OA\Property(
     *                   property="data",
     *                   type="object",
     *                   @OA\Property(property="name", type="array", @OA\Items(type="string",example="The name field is required.")),
     *                   @OA\Property(property="email", type="array", @OA\Items(type="string",example="The email field is required.")),
     *                   @OA\Property(property="password", type="array", @OA\Items(type="string",example="The password field is required.")),
     *              ),
     *          )
     *       ),
     * )
     */

    /**
     * Register a new user.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function register(Request $request)
    {
        try {

            $validator = Validator::make($request->all(), [
                'name' => 'required|string|max:255',
                'email' => 'required|string|email|unique:users,email',
                'password' => 'required|string|min:6'
            ]);

            if ($validator->fails()) {
                return $this->sendError('validation failed', 400, $validator->errors());
            }

            $user = User::create([
                'name' => $request->name,
                'password' => bcrypt($request->password),
                'email' => $request->email
            ]);

            return $this->sendResponse("User signed up in successfully", [
                'user' => new UserResource($user)
            ]);
        } catch (\Throwable $th) {
            // throw $th;
            return $this->sendError($th->getMessage(), 400);
        }
    }

    /**
     * @OA\Post(
     * path="/api/auth/login",
     * summary="Sign in",
     * description="Login by email, password",
     * operationId="Login",
     * tags={"Auth"},
     *  @OA\RequestBody(
     *     required=true,
     *     description="Pass user credentials",
     *     @OA\JsonContent(
     *        required={"email","password"},
     *        @OA\Property(property="email", type="string", format="email", example="john@mail.com"),
     *        @OA\Property(property="password", type="string", format="password", example="PassWord12345"),
     *     ),
     *  ),
     *
     *  @OA\Response(
     *     response=200,
     *     description="Login Successfully",
     *     @OA\JsonContent(
     *         @OA\Property(property="status", type="boolean", example="true"),
     *         @OA\Property(property="message", type="string", example="User logged in successfully"),
     *         @OA\Property(
     *               property="data",
     *               type="object",
     *               @OA\Property(property="user", type="object",
     *                     @OA\Property(property="id", type="integer", example="1"),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="email", type="string", example="John@mail.com"),
     *                     @OA\Property(property="auth_token", type="string", example="3|Wl90TsY0rCGPkkLNllgKDJ0bBBh9Y8fyimN0jl1M")
     *               ),
     *         ),
     *     )
     *  ),
     *
     *   @OA\Response(
     *          response=400,
     *          description="Bad request",
     *          @OA\JsonContent(
     *               @OA\Property(property="status", type="boolean", example="false"),
     *               @OA\Property(property="message", type="string", example="validation failed"),
     *               @OA\Property(
     *                   property="data",
     *                   type="object",
     *                   @OA\Property(property="email", type="array", @OA\Items(type="string",example="The email field is required.")),
     *                   @OA\Property(property="password", type="array", @OA\Items(type="string",example="The password field is required.")),
     *              ),
     *          )
     *       ),
     *
     *  @OA\Response(
     *          response=401,
     *          description="Unauthenticated",
     *          @OA\JsonContent(
     *               @OA\Property(property="status", type="boolean", example="false"),
     *               @OA\Property(property="message", type="string", example="Invalid credentials"),
     *               @OA\Property(
     *                   property="data",
     *                   type="object",
     *              ),
     *          )
     *       ),
     * )
     */

    /**
     * Login User
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */

    public function login(Request $request)
    {

        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|string|email',
                'password' => 'required|string',
            ]);

            if ($validator->fails()) {
                return $this->sendError('validation failed', 400, $validator->errors());
            }

            $credentials = $request->only('email', 'password');

            if (!Auth::attempt($credentials)) {
                return $this->sendError('Invalid credentials', 401);
            }

            $user = auth()->user();

            return $this->sendResponse('User logged in successfully', [
                'user' => new UserResource($user)
            ]);
        } catch (\Throwable $th) {
            //throw $th;
            return $this->sendError($th->getMessage(), 400);
        }
    }

    /**
     * @OA\Post(
     * path="/api/auth/logout",
     * summary="Logout",
     * description="User Logout",
     * operationId="Logout",
     * tags={"Auth"},
     * security={ * {"sanctum": {}}, * },
     *  @OA\Response(
     *     response=200,
     *     description="Logout Successfully",
     *     @OA\JsonContent(
     *         @OA\Property(property="status", type="boolean", example="true"),
     *         @OA\Property(property="message", type="string", example="User logged up in successfully"),
     *         @OA\Property(
     *               property="data",
     *               type="object",
     *         ),
     *     )
     *  ),
     *
     * )
     */
    /**
     * Log out
     */
    public function logout()
    {
        try {

            // Revoke the token that was used to authenticate the current request
            auth()->user()->currentAccessToken()->delete();
            //$request->user->tokens()->delete(); // use this to revoke all tokens (logout from all devices)

            return $this->sendResponse('User logged out successfully');
        } catch (\Throwable $th) {
            //throw $th;
            return $this->sendError($th->getMessage(), 400);
        }
    }

    /**
     * @OA\GET(
     * path="/api/profile",
     * summary="Profile",
     * description="User Profile",
     * operationId="Profile",
     * tags={"Profile"},
     * security={ * {"sanctum": {}}, * },
     *  @OA\Response(
     *     response=200,
     *     description="User Profile Found",
     *     @OA\JsonContent(
     *         @OA\Property(property="status", type="boolean", example="true"),
     *         @OA\Property(property="message", type="string", example="User Profile Found"),
     *         @OA\Property(
     *               property="data",
     *               type="object",
     *               @OA\Property(property="user", type="object",
     *                     @OA\Property(property="id", type="integer", example="1"),
     *                     @OA\Property(property="name", type="string", example="John Doe"),
     *                     @OA\Property(property="email", type="string", example="John@mail.com"),
     *                     @OA\Property(property="auth_token", type="string", example="3|Wl90TsY0rCGPkkLNllgKDJ0bBBh9Y8fyimN0jl1M")
     *               ),
     *         ),
     *     )
     *  ),
     *
     * )
     */
    public function profile()
    {
        try {

            $user = auth()->user();
            return $this->sendResponse('User profile found', [
                'user' => new UserResource($user)
            ]);
        } catch (\Throwable $th) {
            //throw $th;
        }
    }


/**
     * @OA\Post(
     * path="/api/auth/forgot-password",
     * summary="Forgot Password",
     * description="Send Password Reset Link",
     * operationId="Forgot Password",
     * tags={"Auth"},
     *  @OA\RequestBody(
     *     required=true,
     *     description="Pass user email",
     *     @OA\JsonContent(
     *        required={"email"},
     *        @OA\Property(property="email", type="string", format="email", example="john@mail.com")
     *     ),
     *  ),
     *
     *  @OA\Response(
     *     response=200,
     *     description="Password Reset Link Sent Successfully",
     *     @OA\JsonContent(
     *         @OA\Property(property="status", type="boolean", example="true"),
     *         @OA\Property(property="message", type="string", example="Password Reset Link Sent Successfully"),
     *         @OA\Property(
     *               property="data",
     *               type="object"),
     *         ),
     *     )
     *  ),
     *
     *   @OA\Response(
     *          response=400,
     *          description="Bad request",
     *          @OA\JsonContent(
     *               @OA\Property(property="status", type="boolean", example="false"),
     *               @OA\Property(property="message", type="string", example="Error in sending Link"),
     *               @OA\Property(
     *                   property="data",
     *                   type="object"
     *              ),
     *          )
     *       ),
     * )
     */

    public function sendPasswordResetLinkEmail(Request $request)
    {

        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
        ]);

        if ($validator->fails()) {
            return $this->sendError('validation failed', 400, $validator->errors());
        }

        $status = Password::sendResetLink(
            $request->only('email')
        );

        return ($status === Password::RESET_LINK_SENT)
            ? $this->sendResponse('We have sent password reset link to your email')
            : $this->sendError('Error in sending reset link');
    }

    public function resetPassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:8|confirmed',
        ]);

        if ($validator->fails()) {
            return $this->sendError('validation failed', 400, $validator->errors());
        }

        $status = Password::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user, $password) use ($request) {
                $user->forceFill([
                    'password' => Hash::make($password)
                ])->setRememberToken(Str::random(60));

                $user->save();

                event(new PasswordReset($user));
            }
        );

        return ($status === Password::PASSWORD_RESET)
            ? $this->sendResponse($status)
            : $this->sendError($status);
    }
}
