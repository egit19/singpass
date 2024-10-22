<?php

use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Route;

Route::get('/login', [Controller::class, 'index']);
Route::get('/act-login', [Controller::class, 'login']);
Route::get('/callback', [Controller::class, 'callback']);
Route::get('/user', [Controller::class, 'user']);
Route::get('/logout', [Controller::class, 'logout']);

Route::get('/', function () {
    return view('welcome');
});
