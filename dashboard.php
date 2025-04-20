<?php
require 'config.php';
if (!isLoggedIn()) {
    header('Location: index.php');
    exit();
}


$error = '';
$success = '';


$stmt = $pdo->prepare("SELECT id, username, email FROM users WHERE id = ?");
$stmt->execute([$_SESSION['user_id']]);
$user = $stmt->fetch();


$columns = $pdo->query("SHOW COLUMNS FROM users")->fetchAll(PDO::FETCH_COLUMN);
$has_created_at = in_array('created_at', $columns);
$has_last_login = in_array('last_login', $columns);


if ($has_created_at || $has_last_login) {
    $select = "SELECT username, email" . ($has_created_at ? ", created_at" : "") . ($has_last_login ? ", last_login" : "") . " FROM users WHERE id = ?";
    $stmt = $pdo->prepare($select);
    $stmt->execute([$_SESSION['user_id']]);
    $user = $stmt->fetch();
}


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  
    if (isset($_POST['update_email'])) {
        $new_email = trim($_POST['email'] ?? '');
        
        if (!filter_var($new_email, FILTER_VALIDATE_EMAIL)) {
            $error = 'Invalid email format';
        } else {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ? AND id != ?");
            $stmt->execute([$new_email, $_SESSION['user_id']]);
            if ($stmt->rowCount() > 0) {
                $error = 'Email already in use';
            } else {
                $stmt = $pdo->prepare("UPDATE users SET email = ? WHERE id = ?");
                if ($stmt->execute([$new_email, $_SESSION['user_id']])) {
                    $success = 'Email updated successfully!';
                    $user['email'] = $new_email;
                } else {
                    $error = 'Failed to update email';
                }
            }
        }
    }
    
 
    if (isset($_POST['update_password'])) {
        $current_password = trim($_POST['current_password'] ?? '');
        $new_password = trim($_POST['new_password'] ?? '');
        $confirm_password = trim($_POST['confirm_password'] ?? '');

        if (empty($current_password) || empty($new_password) || empty($confirm_password)) {
            $error = 'Please fill all password fields';
        } elseif ($new_password !== $confirm_password) {
            $error = 'New passwords do not match';
        } elseif (strlen($new_password) < 6) {
            $error = 'New password must be at least 6 characters';
        } else {
            $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $current_hashed = $stmt->fetchColumn();
            
            if (password_verify($current_password, $current_hashed)) {
                $new_hashed = password_hash($new_password, PASSWORD_DEFAULT);
                $stmt = $pdo->prepare("UPDATE users SET password = ? WHERE id = ?");
                if ($stmt->execute([$new_hashed, $_SESSION['user_id']])) {
                    $success = 'Password updated successfully!';
                } else {
                    $error = 'Failed to update password';
                }
            } else {
                $error = 'Current password is incorrect';
            }
        }
    }
    
    
    if (isset($_POST['update_profile'])) {
        $new_username = trim($_POST['username'] ?? '');
        
        if (empty($new_username)) {
            $error = 'Username cannot be empty';
        } elseif (strlen($new_username) < 3) {
            $error = 'Username must be at least 3 characters';
        } else {
            $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
            $stmt->execute([$new_username, $_SESSION['user_id']]);
            if ($stmt->rowCount() > 0) {
                $error = 'Username already in use';
            } else {
                $stmt = $pdo->prepare("UPDATE users SET username = ? WHERE id = ?");
                if ($stmt->execute([$new_username, $_SESSION['user_id']])) {
                    $success = 'Profile updated successfully!';
                    $user['username'] = $new_username;
                } else {
                    $error = 'Failed to update profile';
                }
            }
        }
    }
    
    
    if (isset($_POST['delete_account'])) {
        $password = trim($_POST['password'] ?? '');
        $confirm = trim($_POST['confirm'] ?? '');
        
        if (empty($password)) {
            $error = 'Please enter your password';
        } elseif ($confirm !== 'DELETE') {
            $error = 'Please type "DELETE" to confirm';
        } else {
            $stmt = $pdo->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->execute([$_SESSION['user_id']]);
            $hashed_password = $stmt->fetchColumn();
            
            if (password_verify($password, $hashed_password)) {
                $stmt = $pdo->prepare("DELETE FROM users WHERE id = ?");
                if ($stmt->execute([$_SESSION['user_id']])) {
                    session_destroy();
                    header('Location: index.php?account_deleted=1');
                    exit();
                } else {
                    $error = 'Failed to delete account';
                }
            } else {
                $error = 'Incorrect password';
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard</title>
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        .dashboard {
            max-width: 800px;
            margin: 20px auto;
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .nav-tabs {
            display: flex;
            border-bottom: 1px solid #ddd;
            margin-bottom: 20px;
        }
        .nav-tabs button {
            flex: 1;
            padding: 10px;
            border: none;
            background: #f8f9fa;
            cursor: pointer;
            font-size: 16px;
            transition: background 0.3s;
        }
        .nav-tabs button.active, .nav-tabs button:hover {
            background: #007bff;
            color: #fff;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .profile-info p {
            margin: 10px 0;
            font-size: 16px;
        }
        .logout-btn, .btn {
            display: inline-block;
            margin-top: 20px;
            padding: 10px 20px;
            color: #fff;
            text-decoration: none;
            border-radius: 4px;
            border: none;
            cursor: pointer;
        }
        .logout-btn {
            background: #dc3545;
        }
        .logout-btn:hover {
            background: #c82333;
        }
        .btn {
            background: #28a745;
        }
        .btn:hover {
            background: #218838;
        }
        .btn-danger {
            background: #dc3545;
        }
        .btn-danger:hover {
            background: #c82333;
        }
        .input-group {
            margin-bottom: 15px;
        }
        .input-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        .input-group input {
            width: 100%;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .password-container {
            position: relative;
        }
        .password-toggle {
            position: absolute;
            right: 10px;
            top: 35px;
            cursor: pointer;
        }
        .error {
            color: #dc3545;
            margin-bottom: 15px;
            padding: 10px;
            background: #f8d7da;
            border-radius: 4px;
        }
        .success {
            color: #28a745;
            margin-bottom: 15px;
            padding: 10px;
            background: #d4edda;
            border-radius: 4px;
        }
        @media (max-width: 600px) {
            .nav-tabs {
                flex-direction: column;
            }
            .nav-tabs button {
                width: 100%;
                margin-bottom: 5px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="dashboard">
            <h2>Welcome, <?= htmlspecialchars($user['username']) ?>!</h2>
            <?php if (!empty($error)): ?>
                <div class="error"><?= htmlspecialchars($error) ?></div>
            <?php endif; ?>
            <?php if (!empty($success)): ?>
                <div class="success"><?= htmlspecialchars($success) ?></div>
            <?php endif; ?>
            
            <div class="nav-tabs">
                <button class="tab-button active" onclick="openTab('profile')">Profile</button>
                <button class="tab-button" onclick="openTab('email')">Email</button>
                <button class="tab-button" onclick="openTab('password')">Password</button>
                <button class="tab-button" onclick="openTab('delete')">Delete Account</button>
            </div>
            
           
            <div id="profile" class="tab-content active">
                <h3>Profile Information</h3>
                <div class="profile-info">
                    <p><strong>Username:</strong> <?= htmlspecialchars($user['username']) ?></p>
                    <p><strong>Email:</strong> <?= htmlspecialchars($user['email']) ?></p>
                    <?php if ($has_created_at && !empty($user['created_at'])): ?>
                        <p><strong>Joined:</strong> <?= date('F j, Y', strtotime($user['created_at'])) ?></p>
                    <?php endif; ?>
                    <?php if ($has_last_login && !empty($user['last_login'])): ?>
                        <p><strong>Last Login:</strong> <?= date('F j, Y, g:i a', strtotime($user['last_login'])) ?></p>
                    <?php endif; ?>
                </div>
                
                <h3 style="margin-top: 20px;">Update Profile</h3>
                <form method="post">
                    <input type="hidden" name="update_profile">
                    <div class="input-group">
                        <label>Username</label>
                        <input type="text" name="username" value="<?= htmlspecialchars($user['username']) ?>" required>
                    </div>
                    <button type="submit" class="btn">Update Profile</button>
                </form>
            </div>
            
            
            <div id="email" class="tab-content">
                <h3>Update Email</h3>
                <form method="post">
                    <input type="hidden" name="update_email">
                    <div class="input-group">
                        <label>Current Email</label>
                        <input type="text" value="<?= htmlspecialchars($user['email']) ?>" disabled>
                    </div>
                    <div class="input-group">
                        <label>New Email</label>
                        <input type="email" name="email" value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required>
                    </div>
                    <button type="submit" class="btn">Update Email</button>
                </form>
            </div>
            
            
            <div id="password" class="tab-content">
                <h3>Update Password</h3>
                <form method="post">
                    <input type="hidden" name="update_password">
                    <div class="input-group password-container">
                        <label>Current Password</label>
                        <input type="password" name="current_password" id="current-password" required>
                        <span class="password-toggle" onclick="togglePassword('current-password')">
                            <i class="fas fa-eye"></i>
                        </span>
                    </div>
                    <div class="input-group password-container">
                        <label>New Password</label>
                        <input type="password" name="new_password" id="new-password" required>
                        <span class="password-toggle" onclick="togglePassword('new-password')">
                            <i class="fas fa-eye"></i>
                        </span>
                    </div>
                    <div class="input-group password-container">
                        <label>Confirm New Password</label>
                        <input type="password" name="confirm_password" id="confirm-password" required>
                        <span class="password-toggle" onclick="togglePassword('confirm-password')">
                            <i class="fas fa-eye"></i>
                        </span>
                    </div>
                    <button type="submit" class="btn">Update Password</button>
                </form>
            </div>
            
            
            <div id="delete" class="tab-content">
                <h3>Delete Account</h3>
                <div class="warning" style="color: #dc3545; margin-bottom: 20px;">
                    <p><strong>Warning:</strong> This action is irreversible. All your data will be permanently deleted.</p>
                </div>
                <form method="post" onsubmit="return confirm('Are you absolutely sure you want to delete your account? This cannot be undone!');">
                    <input type="hidden" name="delete_account">
                    <div class="input-group password-container">
                        <label>Enter Your Password</label>
                        <input type="password" name="password" required>
                    </div>
                    <div class="input-group">
                        <label>Type "DELETE" to confirm</label>
                        <input type="text" name="confirm" required>
                    </div>
                    <button type="submit" class="btn btn-danger">Delete My Account</button>
                </form>
            </div>
            
            <a href="logout.php" class="logout-btn" onclick="return confirm('Are you sure you want to logout?')">
                <i class="fas fa-sign-out-alt"></i> Logout
            </a>
        </div>
    </div>

    <script>
    function openTab(tabName) {
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.querySelectorAll('.tab-button').forEach(button => {
            button.classList.remove('active');
        });
        document.getElementById(tabName).classList.add('active');
        document.querySelector(`button[onclick="openTab('${tabName}')"]`).classList.add('active');
    }

    function togglePassword(inputId) {
        const input = document.getElementById(inputId);
        const icon = input.nextElementSibling.querySelector('i');
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