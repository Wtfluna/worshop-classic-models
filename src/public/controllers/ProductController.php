<?php

declare(strict_types=1);

require_once 'public/db/Database.php';

class ProductController
{
    private Database $db;

    public function __construct()
    {
        $this->db = new Database();
    }

    public function index()
    {
        try {
            // 2 - Requête SQL pour récupérer la liste des produits
            $stmt = $this->db->query(
                "SELECT * FROM products LIMIT 20"
            );
            $products = $stmt->fetchAll(PDO::FETCH_ASSOC);

            // 3 - Affichage de la liste des produits
            include 'public/views/layout/header.view.php';
            include 'public/views/index.view.php';
            include 'public/views/layout/footer.view.php';
        } catch (Exception $e) {
            print_r($e->getMessage());
        }
    }

    public function show(string $productCode)
    {
        try {
            $stmt = $this->db->query(
                "SELECT * FROM products WHERE productCode = ?",
                [$productCode]
            );
            $product = $stmt->fetch(PDO::FETCH_ASSOC);

            if (empty($product)) {
                echo '404 - no product found';
                die;
            }

            // 3 - Afficher la page
            include 'public/views/layout/header.view.php';
            include 'public/views/product.view.php';
            include 'public/views/layout/footer.view.php';
        } catch (Exception $e) {
            print_r($e->getMessage());
        }
    }
}
