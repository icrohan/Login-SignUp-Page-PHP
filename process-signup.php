<?php

if (empty($_POST["name"])) {
    die("Name is required");
}

if (!filter_var($_POST["email"], FILTER_VALIDATE_EMAIL)) {
    die("Valid email is required");
}

if (strlen($_POST["password"]) < 8) {
    die("Password must be at least 8 characters");
}

if (!preg_match("/[a-z]/i", $_POST["password"])) {
    die("Password must contain at least one letter");
}

if (!preg_match("/[0-9]/", $_POST["password"])) {
    die("Password must contain at least one number");
}

if ($_POST["password"] !== $_POST["password_confirmation"]) {
    die("Passwords must match");
}

$password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

// Check if email already exists
$sql_check_email = "SELECT COUNT(*) AS count FROM user WHERE email = ?";
$stmt_check_email = $mysqli->prepare($sql_check_email);

if (!$stmt_check_email) {
    die("SQL error: " . $mysqli->error);
}

$stmt_check_email->bind_param("s", $_POST["email"]);
$stmt_check_email->execute();
$result_check_email = $stmt_check_email->get_result();
$row = $result_check_email->fetch_assoc();
$count = $row['count'];

if ($count > 0) {
    die("Email already taken");
}

// If email is not taken, proceed with insertion
$sql_insert_user = "INSERT INTO user (name, email, password_hash) VALUES (?, ?, ?)";
$stmt_insert_user = $mysqli->prepare($sql_insert_user);

if (!$stmt_insert_user) {
    die("SQL error: " . $mysqli->error);
}

$stmt_insert_user->bind_param("sss", $_POST["name"], $_POST["email"], $password_hash);

if ($stmt_insert_user->execute()) {
    header("Location: signup-success.html");
    exit;
} else {
    die("Error inserting user: " . $mysqli->error);
}









