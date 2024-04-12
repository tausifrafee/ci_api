<?php
namespace App\Controllers;

use App\Models\UserModel;
use CodeIgniter\HTTP\Response;
use CodeIgniter\HTTP\ResponseInterface;
use Exception;
use ReflectionException;
use Ramsey\Uuid\Uuid;
use CodeIgniter\API\ResponseTrait;
use Firebase\JWT\JWT;

class Auth extends BaseController
{
    /**
     * Register a new user
     * @return Response
     * @throws ReflectionException
     */

     use ResponseTrait;

     public function register()
     {
         try {
             // Get POST data
             $name = $this->request->getPost('name');
             $email = $this->request->getPost('email');
             $password = $this->request->getPost('password');
 
             // Validate input (add more validation rules as needed)
             if (empty($name) || empty($email) || empty($password)) {
                 return $this->failValidationError('Name, email, and password are required');
             }
 
             // Generate JWT token
            //  $jwtToken = $this->generateJWT($email);
             $apiKey = $this->generateApiKey($email);

             // Save user to database
             $userModel = new UserModel();
             $userData = [
                 'name' => $name,
                 'email' => $email,
                 'password' => $password, // Note: In a real application, hash the password before saving
                 'api_key' => $apiKey,
             ];
             $userModel->insert($userData);
 
             // Return success response with JWT token and user info
             return $this->respond([
                 'status' => 'success',
                 'message' => 'User registered successfully',
                 'user' => $userData,
                //  'jwt_token' => $jwtToken,
                 'api_key' => $apiKey,
             ]);
         } catch (\CodeIgniter\Database\Exceptions\DatabaseException $e) {
             // Check if the error is due to a duplicate entry
             if (strpos($e->getMessage(), 'Duplicate entry') !== false) {
                 return $this->failValidationError('Email address is already registered');
             }
 
             // Log the exception
             log_message('error', 'Database exception occurred during user registration: ' . $e->getMessage());
 
             // Return a generic error response
             return $this->failServerError('An unexpected error occurred. Please try again later.');
         } catch (Exception $e) {
             // Log the exception
             log_message('error', 'Exception occurred during user registration: ' . $e->getMessage());
 
             // Return a generic error response
             return $this->failServerError('An unexpected error occurred. Please try again later.');
         }
     }

     private function generateApiKey($email)
     {
         // Generate a unique API key (you can use any method to generate a key)
         return bin2hex(random_bytes(16)); // Example: Generate a 32-character hexadecimal string
     }
 
     // Generate JWT token
     private function generateJWT($email)
     {
         try {
             $key = getenv('JWT_SECRET_KEY'); // Load secret key from environment or config
             $payload = [
                 'email' => $email,
                 'exp' => time() + 3600, // Token expiration time (e.g., 1 hour)
             ];
             return JWT::encode($payload, $key);
         } catch (Exception $e) {
             // Log the exception
             log_message('error', 'Exception occurred during JWT token generation: ' . $e->getMessage());
 
             // Return the error message in the API response
             return $this->respond([
                 'status' => 'error',
                 'message' => 'Failed to generate JWT token: ' . $e->getMessage(),
             ], ResponseInterface::HTTP_INTERNAL_SERVER_ERROR);
         }
     }


    /**
     * Authenticate Existing User
     * @return Response
     */

    use ResponseTrait;

    public function login()
    {
        try {
            // Get API key from the request headers
            $apiKey = $this->request->getHeaderLine('X-API-Key');

            // Validate API key (add more validation as needed)
            if (empty($apiKey)) {
                return $this->failUnauthorized('API key is required');
            }

            // Retrieve user from the database by API key
            $userModel = new UserModel();
            $user = $userModel->where('api_key', $apiKey)->first();

            // Check if user exists
            if (!$user) {
                return $this->failNotFound('Invalid API key');
            }

            // Get email and password from the request
            $email = $this->request->getPost('email');
            $password = $this->request->getPost('password');
            

            // Validate email and password (add more validation as needed)
            if (empty($email) || empty($password)) {
                return $this->failValidationError('Email and password are required');
            }
            
            // Retrieve user from the database by email
            $userByEmail = $userModel->where('email', $email)->first();

            // Check if user exists with the provided email
            if (!$userByEmail) {
                return $this->failNotFound('User not found');
            }

            // Check if the user's email is verified
            if (!$userByEmail['email']) {
                return $this->failUnauthorized('Email not verified. Please check your email for verification instructions.');
            }

            // Verify password
            if (!password_verify($password, $user['password'])) {
                return $this->failUnauthorized('Incorrect password');
            }

            // Authentication successful, return success response
            return $this->respond([
                'status' => 'success',
                'message' => 'User authenticated successfully',
                'user' => $user, // Optionally, you can include user data in the response
            ]);
        } catch (Exception $e) {
            // Log the exception
            log_message('error', 'Exception occurred during user login: ' . $e->getMessage());

            // Return a generic error response
            return $this->failServerError('An unexpected error occurred. Please try again later.');
        }
    }

    private function getJWTForUser(string $emailAddress): string
    {
        try {
            $model = new UserModel();
            $user = $model->findUserByEmailAddress($emailAddress);
            unset($user['password']);

            helper('jwt');

            // Generate and return the access token
            return getSignedJWTForUser($emailAddress);
        } catch (Exception $exception) {
            // Handle exception (e.g., log error)
            return 'error getting jwt'; // Return empty string or handle error condition as needed
        }
    }

}