<?php

namespace App\Traits;


/*
|--------------------------------------------------------------------------
| Api Responser Trait
|--------------------------------------------------------------------------
|
| This trait will be used for any response we sent to clients.
|
*/

trait ApiResponser
{
    /**
     * Return a success JSON response.
     *
     * @param  array|string  $data
     * @param  string  $message
     * @param  int|null  $code
     * @return \Illuminate\Http\JsonResponse
     */
    protected function sendResponse(string $message = null, $data = null, int $code = 200)
    {
        return response()->json([
            'status' => true,
            'message' => $message,
            'data' => $data ?? (object) []
        ], $code);
    }

    /**
     * Return an error JSON response.
     *
     * @param  string  $message
     * @param  int  $code
     * @param  array|string|null  $data
     * @return \Illuminate\Http\JsonResponse
     */
    protected function sendError(string $message = null, int $code = 400, $data = null)
    {
        return response()->json([
            'status' => false,
            'message' => $message,
            'data' => $data ?? (object) []
        ], $code);
    }
}
