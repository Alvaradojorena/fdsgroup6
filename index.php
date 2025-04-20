<?php 
require 'config.php';


$error = '';


if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit();
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (!empty($username) && !empty($password)) {
        $stmt = $pdo->prepare("SELECT id, username, password FROM users WHERE username = ? OR email = ?");
        $stmt->execute([$username, $username]);
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            header('Location: dashboard.php');
            exit();
        } else {
            $error = 'Invalid username or password';
        }
    } else {
        $error = 'Please fill all fields';
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
            <h2>Login Form Project</h2>
            <?php if (!empty($error)): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <form method="post">
                <div class="input-group">
                    <label>Username or Email</label>
                    <i class="icon fas fa-user"></i>
                    <input type="text" name="username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required>
                </div>
                <div class="input-group">
                    <label>Password</label>
                    <i class="icon fas fa-lock"></i>
                    <input type="password" name="password" id="login-password" required>
                    <span class="password-toggle" onclick="togglePassword('login-password', this)">
                        <i class="fas fa-eye"></i>
                    </span>
                </div>
                <button type="submit" class="btn">Login</button>
            </form>
            <div class="link">
                Don't have an account? <a href="register.php">Register</a>
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