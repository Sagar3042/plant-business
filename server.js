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

// --- 1. MONGODB DATABASE CONNECTION ---
// আপনার নতুন অ্যাডমিন ইউজারনেম ও পাসওয়ার্ড দিয়ে কানেকশন
const MONGO_URI = "mongodb+srv://admin:sagar12345@cluster0.str6vtc.mongodb.net/?appName=Cluster0";

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected Successfully!"))
    .catch(err => console.error("❌ DB Connection Error:", err));

// --- 2. ENCRYPTION SETUP (AES-256) ---
// টাকার অংক এবং পার্সোনাল ডাটা এনক্রিপ্ট করার চাবি
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

// --- 3. DATABASE MODELS ---

// খরচের হিসাব (কে এড করল, সময়, আইটেমের নাম সহ)
const expenseSchema = new mongoose.Schema({
    date: String,      // YYYY-MM-DD
    time: String,      // 10:30 PM
    category: String,  // Plant / Other
    itemName: String,  // Rose / Pot / Tea
    amount: String,    // Encrypted
    addedBy: String    // Ujjal / Sagar etc.
});

// ফান্ডের হিসাব (কে কত টাকা দিল)
const fundSchema = new mongoose.Schema({
    name: String,
    amount: String, // Encrypted
    date: String
});

// ইউজার একাউন্ট (পার্টনারদের লগইন)
const userSchema = new mongoose.Schema({
    username: String,
    password: String, 
    role: String, // 'admin' or 'partner'
    name: String
});

// লগইন হিস্ট্রি (কে কখন ঢুকল)
const logSchema = new mongoose.Schema({
    name: String,
    loginTime: String,
    date: String
});

const Expense = mongoose.model('Expense', expenseSchema);
const Fund = mongoose.model('Fund', fundSchema);
const User = mongoose.model('User', userSchema);
const Log = mongoose.model('Log', logSchema);

// --- 4. SESSION SETUP (লগইন ধরে রাখার জন্য) ---
app.use(session({
    secret: 'super-secure-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // ৩০ দিন লগইন থাকবে
}));

// --- 5. API ROUTES ---

// === LOGIN SYSTEM ===
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    // A. MAIN ADMIN CHECK (Fixed ID/Pass)
    if (username === '9328472337' && password === 'sagar') {
        req.session.user = { name: 'Sagar (Admin)', role: 'admin' };
        
        // Save History
        await Log.create({ 
            name: 'Admin', 
            loginTime: new Date().toLocaleTimeString(), 
            date: new Date().toLocaleDateString() 
        });
        
        return res.json({ success: true, role: 'admin' });
    }

    // B. PARTNER CHECK (Database)
    const user = await User.findOne({ username, password });
    if (user) {
        req.session.user = { name: user.name, role: user.role };
        
        // Save History
        await Log.create({ 
            name: user.name, 
            loginTime: new Date().toLocaleTimeString(), 
            date: new Date().toLocaleDateString() 
        });
        
        return res.json({ success: true, role: user.role });
    }

    res.status(401).json({ success: false, message: 'ভুল ইউজারনেম বা পাসওয়ার্ড!' });
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/session', (req, res) => {
    if (req.session.user) {
        res.json({ loggedIn: true, role: req.session.user.role, name: req.session.user.name });
    } else {
        res.json({ loggedIn: false });
    }
});

// MIDDLEWARE (Security Check)
function requireLogin(req, res, next) {
    if (req.session.user) next();
    else res.status(401).json({ error: 'Unauthorized' });
}

// === EXPENSE MANAGEMENT ===

// 1. Add Expense (সবাই পারবে)
app.post('/api/expense', requireLogin, async (req, res) => {
    const { date, time, category, itemName, amount } = req.body;
    await Expense.create({
        date, 
        time, 
        category, 
        itemName,
        amount: encrypt(amount),
        addedBy: req.session.user.name
    });
    res.json({ message: 'Saved' });
});

// 2. Get Expense List (By Date)
app.get('/api/expense', requireLogin, async (req, res) => {
    const { date } = req.query; // Client will send ?date=2023-10-25
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

// 3. Get Monthly Summary (For Graph)
app.get('/api/summary', requireLogin, async (req, res) => {
    const allExp = await Expense.find();
    let plantTotal = 0;
    let otherTotal = 0;
    
    const currentMonth = new Date().getMonth(); // Current Month Index (0-11)
    const currentYear = new Date().getFullYear();

    allExp.forEach(ex => {
        const d = new Date(ex.date);
        // Check if same month and year
        if (d.getMonth() === currentMonth && d.getFullYear() === currentYear) {
            const amt = parseFloat(decrypt(ex.amount));
            if (ex.category === 'Plant') plantTotal += amt;
            else otherTotal += amt;
        }
    });
    
    res.json({ plant: plantTotal, other: otherTotal });
});

// === ADMIN FEATURES (Fund & User) ===

// 1. Create New Partner (Admin Only)
app.post('/api/create-user', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Only Admin Allowed"});
    
    const { name, username, password } = req.body;
    // Check if user exists
    const existing = await User.findOne({ username });
    if(existing) return res.status(400).json({msg: "User already exists"});

    await User.create({ name, username, password, role: 'partner' });
    res.json({ message: 'User Created Successfully' });
});

// 2. Add Fund (Admin Only)
app.post('/api/fund', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Only Admin Allowed"});
    
    const { name, amount, date } = req.body;
    await Fund.create({ name, amount: encrypt(amount), date });
    res.json({ message: 'Fund Added' });
});

// 3. Get Fund List
app.get('/api/fund', requireLogin, async (req, res) => {
    const funds = await Fund.find().sort({ date: -1 });
    const data = funds.map(f => ({
        name: f.name,
        amount: decrypt(f.amount),
        date: f.date
    }));
    res.json(data);
});

// 4. Get Login History (Admin Only)
app.get('/api/logs', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    
    const logs = await Log.find().sort({_id: -1}).limit(20);
    res.json(logs);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));