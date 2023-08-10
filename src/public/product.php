<?php

declare(strict_types=1);

require 'public/controllers/ProductController.php';

session_start();

$productController = new ProductController();

$productController->show($_GET['productCode']);
