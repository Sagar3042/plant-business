const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const crypto = require('crypto');
const session = require('express-session');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors());
app.use(express.static('public'));

// --- MONGODB CONNECTION ---
const MONGO_URI = "mongodb+srv://prakritidost_db_user:sagar@cluster0.str6vtc.mongodb.net/?appName=Cluster0";

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected! System Ready."))
    .catch(err => console.error("❌ DB Error:", err));

// --- ENCRYPTION SETUP ---
const ENCRYPTION_KEY = crypto.scryptSync('my-secret-business-password', 'salt', 32); 
const IV_LENGTH = 16; 

function encrypt(text) {
    if (!text) text = "0";
    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
    let encrypted = cipher.update(text.toString());
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(text) {
    if (!text) return "0";
    try {
        let textParts = text.split(':');
        let iv = Buffer.from(textParts.shift(), 'hex');
        let encryptedText = Buffer.from(textParts.join(':'), 'hex');
        let decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(ENCRYPTION_KEY), iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) { return "Error"; }
}

// --- DATABASE MODELS ---
// 1. Expense (Added 'addedBy' and 'time')
const expenseSchema = new mongoose.Schema({
    date: String,
    time: String,
    category: String,
    itemName: String,
    amount: String, // Encrypted
    addedBy: String // কে এড করেছে (Ujjal/Sagar etc)
});

// 2. Fund (Tracks who gave money and when)
const fundSchema = new mongoose.Schema({
    name: String,
    amount: String, // Encrypted
    date: String
});

// 3. User (For login management)
const userSchema = new mongoose.Schema({
    username: String,
    password: String, // In real app, hash this!
    role: String, // 'admin' or 'partner'
    name: String
});

// 4. Login History
const logSchema = new mongoose.Schema({
    name: String,
    loginTime: String,
    date: String
});

const Expense = mongoose.model('Expense', expenseSchema);
const Fund = mongoose.model('Fund', fundSchema);
const User = mongoose.model('User', userSchema);
const Log = mongoose.model('Log', logSchema);

// --- SESSION SETUP (Persistent Login) ---
app.use(session({
    secret: 'super-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // ৩০ দিন লগইন থাকবে
}));

// --- API ROUTES ---

// 1. LOGIN API
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // A. Check for MAIN ADMIN
    if (username === '9328472337' && password === 'sagar') {
        req.session.user = { name: 'Sagar (Admin)', role: 'admin' };
        // Log History
        await Log.create({ name: 'Admin', loginTime: new Date().toLocaleTimeString(), date: new Date().toLocaleDateString() });
        return res.json({ success: true, role: 'admin' });
    }

    // B. Check for Created Users (Partners)
    const user = await User.findOne({ username, password });
    if (user) {
        req.session.user = { name: user.name, role: user.role };
        // Log History
        await Log.create({ name: user.name, loginTime: new Date().toLocaleTimeString(), date: new Date().toLocaleDateString() });
        return res.json({ success: true, role: user.role });
    }

    res.status(401).json({ success: false, message: 'ভুল ইউজারনেম বা পাসওয়ার্ড!' });
});

// Logout
app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

// Check Session
app.get('/api/session', (req, res) => {
    if (req.session.user) res.json({ loggedIn: true, role: req.session.user.role, name: req.session.user.name });
    else res.json({ loggedIn: false });
});

// Middleware
function requireLogin(req, res, next) {
    if (req.session.user) next();
    else res.status(401).json({ error: 'Unauthorized' });
}

// --- EXPENSE ROUTES ---

// Add Expense (সবাই পারবে)
app.post('/api/expense', requireLogin, async (req, res) => {
    const { date, time, category, itemName, amount } = req.body;
    await Expense.create({
        date, time, category, itemName,
        amount: encrypt(amount),
        addedBy: req.session.user.name
    });
    res.json({ message: 'Saved' });
});

// Get Expense by DATE
app.get('/api/expense', requireLogin, async (req, res) => {
    const { date } = req.query; // e.g., ?date=2023-10-25
    let query = {};
    if(date) query = { date: date };
    
    const expenses = await Expense.find(query).sort({_id: -1});
    const data = expenses.map(r => ({
        date: r.date,
        time: r.time,
        category: r.category,
        itemName: r.itemName,
        amount: decrypt(r.amount),
        addedBy: r.addedBy
    }));
    res.json(data);
});

// Get Monthly Summary for Chart
app.get('/api/summary', requireLogin, async (req, res) => {
    // এখানে আমরা সব ডাটা এনে ফিল্টার করব (সিম্পল লজিক)
    const allExp = await Expense.find();
    let plantTotal = 0;
    let otherTotal = 0;
    
    // চলতি মাসের নাম বের করা
    const currentMonth = new Date().getMonth(); // 0-11
    
    allExp.forEach(ex => {
        const d = new Date(ex.date);
        if (d.getMonth() === currentMonth) {
            const amt = parseFloat(decrypt(ex.amount));
            if (ex.category === 'Plant') plantTotal += amt;
            else otherTotal += amt;
        }
    });
    
    res.json({ plant: plantTotal, other: otherTotal });
});

// --- FUND & USER MANAGEMENT (Admin Only) ---

// Create User (Admin Only)
app.post('/api/create-user', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    const { name, username, password } = req.body;
    await User.create({ name, username, password, role: 'partner' });
    res.json({ message: 'User Created' });
});

// Add Fund Record (Admin Only)
app.post('/api/fund', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    const { name, amount, date } = req.body;
    await Fund.create({ name, amount: encrypt(amount), date });
    res.json({ message: 'Fund Added' });
});

// Get Fund List
app.get('/api/fund', requireLogin, async (req, res) => {
    const funds = await Fund.find().sort({ date: -1 });
    const data = funds.map(f => ({
        name: f.name,
        amount: decrypt(f.amount),
        date: f.date
    }));
    res.json(data);
});

// Get Login Logs (Admin Only)
app.get('/api/logs', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    const logs = await Log.find().sort({_id: -1}).limit(20);
    res.json(logs);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));