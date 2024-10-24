// app.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'your_jwt_secret';

// Dummy users database (in a real app, use a database)
const users = [
    { id: 1, username: 'ravi-teja9640', password: bcrypt.hashSync('Ravitejagoud@123', 8), role: 'admin' },
    { id: 2, username: 'user', password: bcrypt.hashSync('user123', 8), role: 'user' }
];

// JWT token generation function
function generateToken(user) {
    return jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
}

// Middleware to verify JWT and roles
function authorizeRoles(allowedRoles) {
    return (req, res, next) => {
        const token = req.headers['authorization'];
        if (!token) return res.status(403).send('No token provided');
        
        jwt.verify(token, SECRET_KEY, (err, decoded) => {
            if (err) return res.status(401).send('Unauthorized');
            
            if (!allowedRoles.includes(decoded.role)) {
                return res.status(403).send('Forbidden');
            }
            
            req.user = decoded; // Save user info for future use
            next();
        });
    };
}

// Login route for generating JWT tokens
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);
        return res.json({ token });
    }
    
    return res.status(401).send('Invalid credentials');
});

// Admin-only route
app.get('/admin', authorizeRoles(['admin']), (req, res) => {
    res.send('Welcome Admin!');
});

// User-only route
app.get('/user', authorizeRoles(['user']), (req, res) => {
    res.send('Welcome User!');
});

// Common route accessible to both admin and user
app.get('/common', authorizeRoles(['admin', 'user']), (req, res) => {
    res.send('This route is accessible by both Admin and User.');
});

// Home route
app.get('/', (req, res) => {
    res.send('Welcome to the Role-Based Authorization System');
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
