<?php

namespace App\Validation;

use App\Models\UserModel;
use Exception;

class UserRules
{
    protected $userModel;

    public function __construct(UserModel $userModel)
    {
        $this->userModel = $userModel;
    }

    public function validateUser(string $str, string $fields, array $data): bool
    {
        try {
            $user = $this->userModel->findUserByEmailAddress($data['email']);
            return password_verify($data['password'], $user['password']);
        } catch (Exception $e) {
            return false;
        }
    }
}
