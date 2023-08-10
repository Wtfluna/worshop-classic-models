<?php

declare(strict_types=1);

require 'public/controllers/AuthController.php';

session_start();

$authController = new AuthController();

$authController->register($_POST['username'], $_POST['email'], $_POST['password']);
