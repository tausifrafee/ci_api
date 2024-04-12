<?php

namespace App\Database\Seeds;

use CodeIgniter\Database\Seeder;

class ClientSeeder extends Seeder
{
    private $names = [
        'John Doe',
        'Jane Smith',
        'Alice Johnson',
        // Add more names as needed
    ];

    private $emails = [
        'john@example.com',
        'jane@example.com',
        'alice@example.com',
        // Add more emails as needed
    ];

    public function run()
    {
        for ($i = 0; $i < 10; $i++) { // to add 10 clients. Change limit as desired
            $this->db->table('client')->insert($this->generateClient());
        }
    }

    private function generateClient(): array
    {
        $nameIndex = array_rand($this->names);
        $emailIndex = array_rand($this->emails);

        return [
            'name' => $this->names[$nameIndex],
            'email' => $this->emails[$emailIndex],
            'retainer_fee' => random_int(100000, 100000000)
        ];
    }
}
