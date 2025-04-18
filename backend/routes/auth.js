const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User, Admin } = require('../db');

// Helper function to generate JWT
const generateToken = (userId, role) => {
    return jwt.sign(
        { id: userId, role },
        process.env.JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Unified login endpoint
router.post('/login', async (req, res) => {
    console.log("🔑 Login request received:", req.body);
    const { identifier, password, role } = req.body;

    if (!identifier || !password || !role) {
        return res.status(400).json({ success: false, message: 'Identifier, password, and role are required' });
    }

    try {
        let user;

        // Check if identifier is an email (contains @ symbol)
        const isEmail = identifier.includes('@');

        if (role === 'admin') {
            // Find admin by username or email
            user = isEmail
                ? await Admin.findOne({ email: identifier })
                : await Admin.findOne({ username: identifier });
        } else {
            // Find candidate by username or email
            user = isEmail
                ? await User.findOne({ email: identifier })
                : await User.findOne({ username: identifier });
        }

        if (!user) {
            console.warn(`⚠️ Invalid ${role} credentials - user not found:`, identifier);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Check if we need to handle legacy non-hashed passwords
        if (user.password === password) {
            // Legacy password - update to hashed version
            console.log(`⚠️ Updating legacy password to hashed version for ${role}:`, user.username);
            user.password = await bcrypt.hash(password, 10);
            await user.save();

            // Generate JWT
            const token = generateToken(user._id, role);

            console.log(`✅ ${role} login successful for:`, user.username);
            return res.json({
                success: true,
                message: 'Login successful',
                role: role,
                token,
                username: user.username
            });
        }

        // Compare hashed password
        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            // Generate JWT
            const token = generateToken(user._id, role);

            console.log(`✅ ${role} login successful for:`, user.username);
            res.json({
                success: true,
                message: 'Login successful',
                role: role,
                token,
                username: user.username
            });
        } else {
            console.warn(`⚠️ Invalid ${role} credentials - password mismatch for:`, user.username);
            res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
    } catch (err) {
        console.error(`❌ Error in ${role} login:`, err);
        res.status(500).json({ success: false, message: 'An error occurred', error: err.message });
    }
});

// Register new user (candidate or admin)
router.post('/register', async (req, res) => {
    console.log("📝 Registration request received:", req.body);
    const { username, password, email, role, registrationCode } = req.body;

    // Validate input
    if (!username || !password) {
        console.warn("⚠️ Registration missing required fields");
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    // Check registration code for admin/HR role
    if (role === 'admin' && registrationCode !== 'itsme@242003') {
        return res.status(400).json({ 
            success: false, 
            message: 'Invalid registration code for admin/HR role' 
        });
    }

    // Basic password validation
    if (password.length < 8) {
        return res.status(400).json({ success: false, message: 'Password must be at least 8 characters long' });
    }

    // Check for password complexity
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?])/;
    if (!passwordRegex.test(password)) {
        return res.status(400).json({
            success: false,
            message: 'Password must include at least one uppercase letter, one lowercase letter, one number, and one special character'
        });
    }

    // Validate email format if provided
    if (email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format' });
        }
    }

    try {
        // Check if username already exists in either User or Admin collection
        const existingUser = await User.findOne({ username });
        const existingAdmin = await Admin.findOne({ username });

        if (existingUser || existingAdmin) {
            console.warn("⚠️ Registration failed - username already exists:", username);
            return res.status(400).json({ success: false, message: 'Username already exists' });
        }

        // Check if email already exists (if provided)
        if (email) {
            const existingUserEmail = await User.findOne({ email });
            const existingAdminEmail = await Admin.findOne({ email });

            if (existingUserEmail || existingAdminEmail) {
                console.warn("⚠️ Registration failed - email already exists");
                return res.status(400).json({ success: false, message: 'Email already exists' });
            }
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new user or admin based on role
        if (role === 'admin') {
            // Create new admin
            const newAdmin = new Admin({
                username,
                password: hashedPassword,
                email: email || null // Email is optional
            });

            const savedAdmin = await newAdmin.save();
            console.log("✅ Admin registered successfully:", username);

            // Success
            res.status(201).json({
                success: true,
                message: 'Admin registration successful',
                user: {
                    id: savedAdmin._id,
                    username: savedAdmin.username,
                    email: savedAdmin.email,
                    role: 'admin'
                }
            });
        } else {
            // Create new candidate
            const newUser = new User({
                username,
                password: hashedPassword,
                email: email || null // Email is optional
            });

            const savedUser = await newUser.save();
            console.log("✅ User registered successfully:", username);

            // Success
            res.status(201).json({
                success: true,
                message: 'Registration successful',
                user: {
                    id: savedUser._id,
                    username: savedUser.username,
                    email: savedUser.email,
                    role: 'candidate'
                }
            });
        }
    } catch (err) {
        console.error('❌ Error in registration:', err);
        res.status(500).json({ success: false, message: 'An error occurred', error: err.message });
    }
});

// Forgot Password
router.post('/forgot-password', async (req, res) => {
    const { identifier } = req.body;
    
    try {
        // Find user by email or username
        const user = await User.findOne({ 
            $or: [
                { email: identifier },
                { username: identifier }
            ]
        }) || await Admin.findOne({ 
            $or: [
                { email: identifier },
                { username: identifier }
            ]
        });

        if (!user) {
            return res.status(404).json({ 
                success: false, 
                message: 'No account found with that email or username' 
            });
        }

        // Generate reset token
        const resetToken = jwt.sign(
            { id: user._id, role: user instanceof Admin ? 'admin' : 'candidate' },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        // TODO: Send email with reset link
        // For now, we'll just return the token
        res.json({ 
            success: true, 
            message: 'Password reset instructions sent to your email',
            token: resetToken // In production, this should be sent via email
        });
    } catch (err) {
        console.error('Error in forgot password:', err);
        res.status(500).json({ success: false, message: 'An error occurred' });
    }
});

// Reset Password
router.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body;

    try {
        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Hash new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Update password based on role
        if (decoded.role === 'admin') {
            await Admin.findByIdAndUpdate(decoded.id, { password: hashedPassword });
        } else {
            await User.findByIdAndUpdate(decoded.id, { password: hashedPassword });
        }

        res.json({ success: true, message: 'Password reset successful' });
    } catch (err) {
        console.error('Error in reset password:', err);
        res.status(400).json({ success: false, message: 'Invalid or expired token' });
    }
});

// Check if username exists
router.post('/check-username', async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ success: false, message: 'Username is required' });
    }

    try {
        // Check if username exists in either User or Admin collection
        const existingUser = await User.findOne({ username });
        const existingAdmin = await Admin.findOne({ username });

        res.json({
            success: true,
            exists: !!(existingUser || existingAdmin)
        });
    } catch (err) {
        console.error('❌ Error checking username:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred',
            error: err.message
        });
    }
});

// Check if email exists
router.post('/check-email', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
    }

    try {
        // Check if email exists in either User or Admin collection
        const existingUser = await User.findOne({ email });
        const existingAdmin = await Admin.findOne({ email });

        res.json({
            success: true,
            exists: !!(existingUser || existingAdmin)
        });
    } catch (err) {
        console.error('❌ Error checking email:', err);
        res.status(500).json({
            success: false,
            message: 'An error occurred',
            error: err.message
        });
    }
});

module.exports = router; 