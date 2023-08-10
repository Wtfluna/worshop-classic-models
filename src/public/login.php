<?php

declare(strict_types=1);

require 'public/controllers/AuthController.php';

session_start();

$authController = new AuthController();

$authController->login($_POST['username'], $_POST['password']);
