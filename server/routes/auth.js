'use strict';

const express = require('express');
const router = express.Router();
const User = require('../models/User'); // Assuming there is a User model defined
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken'); // Assuming you are using JWT for authentication

// Register
router.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.status(201).json({ message: 'User registered successfully' });
});

// Login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id }, 'your_jwt_secret', { expiresIn: '1h' }); // Change your_jwt_secret to your actual secret
        return res.json({ token });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// Change Password
router.post('/change-password', async (req, res) => {
    const { userId, oldPassword, newPassword } = req.body;
    const user = await User.findById(userId);
    if (user && await bcrypt.compare(oldPassword, user.password)) {
        user.password = await bcrypt.hash(newPassword, 10);
        await user.save();
        return res.json({ message: 'Password changed successfully' });
    }
    res.status(401).json({ message: 'Invalid credentials' });
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
    // Implement your forgot password logic here
    res.json({ message: 'Forgot password request received' });
});

// Reset Password
router.post('/reset-password', async (req, res) => {
    // Implement your reset password logic here
    res.json({ message: 'Password reset successfully' });
});

// Get Current User Profile
router.get('/profile', async (req, res) => {
    const userId = req.user.id; // Assuming you validate JWT and set req.user
    const user = await User.findById(userId);
    res.json(user);
});

// Logout
router.post('/logout', (req, res) => {
    // Logout logic can be handled here
    res.json({ message: 'Logged out successfully' });
});

module.exports = router;
