<?php

declare(strict_types=1);

require_once 'public/db/Database.php';


class AuthController
{

    private Database $db;

    public function __construct()
    {
        $this->db = new Database();
    }

    public function register(string $username, string $email, string $password)
    {
        if (empty($_POST)) {
            // 1 - Afficher le formulaire
            include 'public/views/layout/header.view.php';
            include 'public/views/register.view.php';
            include 'public/views/layout/footer.view.php';
        } else {
            try {
                // 3 - Vérification des données
                // 3.1 - Pas vides ?
                if (empty($username) || empty($email) || empty($password)) {
                    throw new Exception('Formulaire non complet');
                }

                // 3.2 - Pas d'injection SQL ?
                $username = htmlspecialchars($username);
                $email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);

                // 4 - Hasher le mot de passe
                $passwordHash = password_hash($password, PASSWORD_DEFAULT);

                // 5 - Ajout à la base de données

                $stmt = $this->db->query(
                    "
                        INSERT INTO users (username, email, password) 
                        VALUES (?, ?, ?)
                    ",
                    [$username, $email, $passwordHash]
                );

                // 6 - Connexion automatique
                $_SESSION['user'] = [
                    'id' => $db->lastInsertId(),
                    'username' => $username,
                    'email' => $email
                ];

                // Redirect to home page
                http_response_code(302);
                header('location: index.php');
            } catch (Exception $e) {
                echo $e->getMessage();
            }
        }
    }

    public function login(string $username, string $password)
    {
        try {
            if (empty($_POST)) {
                // 1 - Afficher le formulaire
                include 'public/views/layout/header.view.php';
                include 'public/views/login.view.php';
                include 'public/views/layout/footer.view.php';
            } else {
                if (empty($username) || empty($password)) {
                    throw new Exception('Formulaire non complet');
                }

                $username = htmlspecialchars($username);

                $stmt = $this->db->query(
                    "SELECT * FROM users WHERE username = ?",
                    [$username]
                );

                $user = $stmt->fetch();

                if (empty($user)) {
                    throw new Exception('Mauvais nom d\'utilisateur');
                }

                if (password_verify($password, $user['password']) === false) {
                    throw new Exception('Mauvais mot de passe');
                }

                $_SESSION['user'] = [
                    'id' => $user['id'],
                    'username' => $username,
                    'email' => $user['email']
                ];

                // Redirect to home page
                http_response_code(302);
                header('location: index.php');
            }
        } catch (Exception $e) {
            echo $e->getMessage();
        }
    }

    public function logout()
    {
    }
}
