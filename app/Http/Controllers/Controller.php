<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Request;
use Illuminate\Support\Facades\Session;
use Jumbojett\OpenIDConnectClient;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class Controller
{
    public function index(){
        echo view('login');
    }
    
    public function login(Request $request)
    {
        $oidc = new OpenIDConnectClient(
            env('SINGPASS_ISSUER_URL'),
            env('SINGPASS_CLIENT_ID'),
            null 
        );
        
        // Set redirect URL dan scope
        $oidc->setRedirectURL(env('SINGPASS_REDIRECT_URI'));
        $oidc->addScope(['openid']);
        
        // Generate PKCE code_verifier dan code_challenge
        $code_verifier = $this->generateCodeVerifier();
        $code_challenge = $this->generateCodeChallenge($code_verifier);
        
        // Simpan code_verifier ke session untuk digunakan nanti di callback
        Session::put('oidc_auth', ['code_verifier' => $code_verifier]);
        
        // Generate nilai state (token acak) dan simpan ke session
        $state = bin2hex(random_bytes(16)); // Membuat string acak sebagai state
        Session::put('oidc_state', $state);
    
        // Tambahkan code_challenge, code_challenge_method, dan state sebagai parameter otorisasi
        $oidc->addAuthParam([
            'code_challenge' => $code_challenge,
            'code_challenge_method' => 'S256',
            'response_type' => 'code',
            'state' => $state, 
        ]);
        
        // Redirect ke halaman otorisasi Singpass
        return $oidc->authenticate(); 
        
    }

    public function callback(Request $request)
    {

        
        try {
            // Ambil authorization code dari query
            $authorizationCode = $request->input('code');
        
            // Cek apakah authorization code ada
            if (!$authorizationCode) {
                return response()->json(['error' => 'Authorization code not found'], 400);
            }
        
            // Ambil code_verifier dari session
            $oidc_auth = Session::get('oidc_auth');
            $code_verifier = $oidc_auth['code_verifier'] ?? null;
        
            // Cek apakah code_verifier ada
            if (!$code_verifier) {
                return response()->json(['error' => 'Code verifier not found'], 400);
            }

            // Prepare token request URL
            $tokenUrl = env('SINGPASS_ISSUER_URL') . '/token';
        
            // Buat permintaan HTTP POST untuk menukarkan authorization code dengan token
            $client = new \GuzzleHttp\Client();
            $response = $client->post($tokenUrl, [
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'client_id' => env('SINGPASS_CLIENT_ID'),
                    'redirect_uri' => env('SINGPASS_REDIRECT_URI'),
                    'code' => $authorizationCode,
                    'code_verifier' => $code_verifier
                ],
                'http_errors' => false 
            ]);
        
            $statusCode = $response->getStatusCode();
            if ($statusCode != 200) {
                return response()->json(['error' => 'Failed to retrieve token from Singpass', 'status_code' => $statusCode], 401);
            }
        
            // Parse response token
            $tokenData = json_decode($response->getBody()->getContents(), true);
        
            if (!isset($tokenData['id_token'])) {
                return response()->json(['error' => 'ID token not found in response'], 401);
            }
        
            $idToken = $tokenData['id_token'];
                
            Session::put('user', $idToken);
        
            return redirect('/');
        } catch (\Exception $e) {
            return response()->json(['error' => $e->getMessage()], 401);
        }
    }


    public function user(Request $request)
    {
        if (Session::has('user')) {
            return response()->json(Session::get('user'));
        }
        return response()->json(['error' => 'Unauthorized'], 401);
    }

    public function logout(Request $request)
    {
        Session::forget('user');
        return redirect('/');
    }

    private function generateCodeVerifier()
    {
        return bin2hex(random_bytes(32)); 
    }

    private function generateCodeChallenge($code_verifier)
    {
        return rtrim(strtr(base64_encode(hash('sha256', $code_verifier, true)), '+/', '-_'), '=');
    }


}
