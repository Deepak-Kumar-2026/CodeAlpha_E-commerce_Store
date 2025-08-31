// ====== Dependencies ======
require('dotenv').config(); // 
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');

// ====== Initialization ======
const app = express();
const PORT = 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-key';

// ====== Middleware ======
app.use(cors());
app.use(express.json());

// ====== Database Connection ======
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("MongoDB Atlas connected successfully!"))
    .catch(err => console.error("MongoDB connection error:", err));

// ====== Mongoose Schemas & Models ======
// User Schema
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    cart: { type: Object, default: {} }
});
const User = mongoose.model('User', userSchema);

// Product Schema
const productSchema = new mongoose.Schema({
    id: { type: String, required: true, unique: true },
    title: { type: String, required: true },
    price: { type: Number, required: true },
    img: { type: String, required: true },
    category: { type: String, required: true },
    desc: { type: String, required: true },
});
const Product = mongoose.model('Product', productSchema);


// ====== JWT Authentication Middleware ======
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// ====== API Routes ======

// ---- Auth Routes ----
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).json({ msg: 'Please enter all fields.' });

        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ msg: 'User with this email already exists.' });

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();
        res.status(201).json({ msg: 'User registered successfully!' });
    } catch (error) {
        res.status(500).json({ msg: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ msg: 'Invalid credentials.' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials.' });

        const tokenPayload = { id: user._id, name: user.name };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '1h' });

        res.json({ token, user: { id: user._id, name: user.name, email: user.email } });
    } catch (error) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// ---- Product Routes ----
app.get('/api/products', async (req, res) => {
    try {
        const products = await Product.find();
        res.json(products);
    } catch (error) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// ---- Cart Routes (Protected) ----
app.get('/api/cart', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        res.json(user.cart || {});
    } catch (error) {
        res.status(500).json({ msg: 'Server error' });
    }
});

app.post('/api/cart/add', authenticateToken, async (req, res) => {
    try {
        const { productId, quantity } = req.body;
        const user = await User.findById(req.user.id);
        const product = await Product.findOne({ id: productId });
        if (!product) return res.status(404).json({ msg: 'Product not found.' });

        const cart = user.cart || {};
        if (cart[productId]) {
            cart[productId].qty += quantity;
        } else {
            cart[productId] = { ...product.toObject(), qty: quantity };
        }
        
        user.cart = cart;
        await user.save();
        res.status(200).json({ msg: 'Product added to cart', cart: user.cart });
    } catch (error) {
        res.status(500).json({ msg: 'Server error' });
    }
});

// ====== Server Listener ======
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});