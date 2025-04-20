<?php 
require 'config.php';


$error = '';
$success = '';

// Checcking sa login if ni exist na
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}

// mao ni registration form code
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = trim($_POST['password'] ?? '');
    $confirm_password = trim($_POST['confirm_password'] ?? '');

    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $error = 'Please fill all fields';
    } elseif ($password !== $confirm_password) {
        $error = 'Passwords do not match';
    } elseif (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters';
    } else {
        // kung ni exist ang user
        $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $email]);
        
        if ($stmt->rowCount() === 0) {
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            
            if ($stmt->execute([$username, $email, $hashed_password])) {
                $success = 'You created your account successfully!';
                
                $_POST = [];
            } else {
                $error = 'Registration failed';
            }
        } else {
            $error = 'Username or email already exists';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Project</title>
    <link rel="stylesheet" href="style.css">
   
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body>
    <div class="container">
        <div class="form-box">
            <h2>Register Form Project</h2>
            <?php if (!empty($error)): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <div class="success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="input-group">
                    <label>Username</label>
                    <i class="icon fas fa-user"></i>
                    <input type="text" name="username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required>
                </div>
                <div class="input-group">
                    <label>Email</label>
                    <i class="icon fas fa-envelope"></i>
                    <input type="email" name="email" value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required>
                </div>
                <div class="input-group">
                    <label>Password</label>
                    <i class="icon fas fa-lock"></i>
                    <input type="password" name="password" id="reg-password" required>
                    <span class="password-toggle" onclick="togglePassword('reg-password', this)">
                        <i class="fas fa-eye"></i>
                    </span>
                </div>
                <div class="input-group">
                    <label>Confirm Password</label>
                    <i class="icon fas fa-lock"></i>
                    <input type="password" name="confirm_password" id="reg-confirm-password" required>
                    <span class="password-toggle" onclick="togglePassword('reg-confirm-password', this)">
                        <i class="fas fa-eye"></i>
                    </span>
                </div>
                <button type="submit" class="btn">Register</button>
            </form>
            <div class="link">
                Already have an account? <a href="index.php">Login</a>
            </div>
        </div>
    </div>

    <script>
    function togglePassword(inputId, toggleElement) {
        const input = document.getElementById(inputId);
        const icon = toggleElement.querySelector('i');
        if (input.type === "password") {
            input.type = "text";
            icon.classList.replace('fa-eye', 'fa-eye-slash');
        } else {
            input.type = "password";
            icon.classList.replace('fa-eye-slash', 'fa-eye');
        }
    }
    </script>
</body>
</html>