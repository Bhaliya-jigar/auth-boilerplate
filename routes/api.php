<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthenticationController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/
//register new user
Route::prefix('auth')->group(function () {
    Route::post('/signup', [AuthenticationController::class, 'register']);
    Route::post('/login', [AuthenticationController::class, 'login']);
    Route::post('/forgot-password', [AuthenticationController::class, 'sendPasswordResetLinkEmail'])->middleware('throttle:5,1')->name('password.email');
    Route::post('/reset-password', [AuthenticationController::class, 'resetPassword'])->name('password.reset');
});

Route::group(['middleware' => ['auth:sanctum']], function () {
    Route::get('/profile', [AuthenticationController::class, 'profile']);
    Route::post('/auth/logout', [AuthenticationController::class, 'logout']);
});
