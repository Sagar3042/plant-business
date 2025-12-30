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
const MONGO_URI = "mongodb+srv://admin:sagar12345@cluster0.str6vtc.mongodb.net/?appName=Cluster0";

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected!"))
    .catch(err => console.error("❌ DB Error:", err));

// --- ENCRYPTION ---
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

// --- MODELS ---
const expenseSchema = new mongoose.Schema({
    date: String, time: String, category: String, itemName: String, amount: String, addedBy: String
});
const fundSchema = new mongoose.Schema({
    name: String, amount: String, date: String
});
// NEW: কার কাছে কত টাকা আছে (Cash/Online)
const cashHoldingSchema = new mongoose.Schema({
    name: String, type: String, // Cash or Online
    amount: String // Encrypted
});
const userSchema = new mongoose.Schema({
    username: String, password: String, role: String, name: String
});
const logSchema = new mongoose.Schema({
    name: String, loginTime: String, date: String
});

const Expense = mongoose.model('Expense', expenseSchema);
const Fund = mongoose.model('Fund', fundSchema);
const CashHolding = mongoose.model('CashHolding', cashHoldingSchema); // New
const User = mongoose.model('User', userSchema);
const Log = mongoose.model('Log', logSchema);

// --- SESSION ---
app.use(session({
    secret: 'super-secret-key',
    resave: false, saveUninitialized: true,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }
}));

// --- ROUTES ---
// Login
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === '9328472337' && password === 'sagar') {
        req.session.user = { name: 'Sagar (Admin)', role: 'admin' };
        await Log.create({ name: 'Admin', loginTime: new Date().toLocaleTimeString(), date: new Date().toLocaleDateString() });
        return res.json({ success: true, role: 'admin' });
    }
    const user = await User.findOne({ username, password });
    if (user) {
        req.session.user = { name: user.name, role: user.role };
        await Log.create({ name: user.name, loginTime: new Date().toLocaleTimeString(), date: new Date().toLocaleDateString() });
        return res.json({ success: true, role: user.role });
    }
    res.status(401).json({ success: false, message: 'Invalid Credentials' });
});

app.get('/api/logout', (req, res) => { req.session.destroy(); res.json({ success: true }); });
app.get('/api/session', (req, res) => {
    if (req.session.user) res.json({ loggedIn: true, role: req.session.user.role, name: req.session.user.name });
    else res.json({ loggedIn: false });
});
function requireLogin(req, res, next) { if (req.session.user) next(); else res.status(401).json({ error: 'Unauthorized' }); }

// --- EXPENSE ---
app.post('/api/expense', requireLogin, async (req, res) => {
    const { date, time, category, itemName, amount } = req.body;
    await Expense.create({ date, time, category, itemName, amount: encrypt(amount), addedBy: req.session.user.name });
    res.json({ message: 'Saved' });
});
app.put('/api/expense-update', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Admin Only"});
    const { id, itemName, category, amount } = req.body;
    await Expense.findByIdAndUpdate(id, { itemName, category, amount: encrypt(amount) });
    res.json({ message: 'Updated' });
});
app.get('/api/expense', requireLogin, async (req, res) => {
    const { date } = req.query; let query = {}; if(date) query = { date: date };
    const expenses = await Expense.find(query).sort({_id: -1});
    const data = expenses.map(r => ({
        id: r._id, date: r.date, time: r.time, category: r.category,
        itemName: r.itemName, amount: decrypt(r.amount), addedBy: r.addedBy
    }));
    res.json(data);
});
app.get('/api/summary', requireLogin, async (req, res) => {
    const allExp = await Expense.find();
    let plantTotal = 0, otherTotal = 0;
    const currentMonth = new Date().getMonth(); const currentYear = new Date().getFullYear();
    allExp.forEach(ex => {
        const d = new Date(ex.date);
        if (d.getMonth() === currentMonth && d.getFullYear() === currentYear) {
            const amt = parseFloat(decrypt(ex.amount));
            if (ex.category === 'Plant') plantTotal += amt; else otherTotal += amt;
        }
    });
    res.json({ plant: plantTotal, other: otherTotal });
});

// --- FUND & CASH HOLDING MANAGEMENT ---

// 1. Get Financial Overview (Total Fund, Total Expense, Holdings)
app.get('/api/finance-status', requireLogin, async (req, res) => {
    // A. Calculate Total Fund Collected
    const allFunds = await Fund.find();
    let totalFund = 0;
    allFunds.forEach(f => totalTotal = totalFund += parseFloat(decrypt(f.amount)));

    // B. Calculate Total Expense
    const allExpenses = await Expense.find();
    let totalExpense = 0;
    allExpenses.forEach(e => totalExpense += parseFloat(decrypt(e.amount)));

    // C. Get Cash Holdings
    const holdings = await CashHolding.find();
    const holdingData = holdings.map(h => ({
        name: h.name, type: h.type, amount: decrypt(h.amount)
    }));

    res.json({
        totalFund: totalFund,
        totalExpense: totalExpense,
        balance: totalFund - totalExpense,
        holdings: holdingData
    });
});

// 2. Update Cash Holding (Admin Only)
app.post('/api/update-holding', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Admin Only"});
    const { name, type, amount } = req.body;
    
    // Check if entry exists for this person and type
    const existing = await CashHolding.findOne({ name, type });
    if (existing) {
        existing.amount = encrypt(amount);
        await existing.save();
    } else {
        await CashHolding.create({ name, type, amount: encrypt(amount) });
    }
    res.json({ message: 'Holding Updated' });
});

// --- ADMIN ---
app.post('/api/create-user', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    const { name, username, password } = req.body;
    await User.create({ name, username, password, role: 'partner' }); res.json({ message: 'Created' });
});
app.post('/api/fund', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    const { name, amount, date } = req.body;
    await Fund.create({ name, amount: encrypt(amount), date }); res.json({ message: 'Added' });
});
app.get('/api/fund', requireLogin, async (req, res) => {
    const funds = await Fund.find().sort({ date: -1 });
    const data = funds.map(f => ({ name: f.name, amount: decrypt(f.amount), date: f.date }));
    res.json(data);
});
app.get('/api/logs', requireLogin, async (req, res) => {
    if(req.session.user.role !== 'admin') return res.status(403).json({msg: "Not Admin"});
    const logs = await Log.find().sort({_id: -1}).limit(20); res.json(logs);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));