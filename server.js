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

// --- 1. MONGODB CONNECTION (Corrected Link) ---
const MONGO_URI = "mongodb+srv://prakritidost_db_user:sagar@cluster0.str6vtc.mongodb.net/?appName=Cluster0";

mongoose.connect(MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected! Business Data is Safe."))
    .catch(err => console.error("❌ DB Connection Error:", err));

// --- 2. SECURITY & ENCRYPTION ---
const ENCRYPTION_KEY = crypto.scryptSync('my-secret-password', 'salt', 32); 
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

// --- 3. DATABASE SCHEMAS ---
const expenseSchema = new mongoose.Schema({
    date: String,
    category: String,
    amount: String, // Encrypted
    description: String
});
const partnerSchema = new mongoose.Schema({
    name: String,
    given: String, // Encrypted
    due: String    // Encrypted
});

const Expense = mongoose.model('Expense', expenseSchema);
const Partner = mongoose.model('Partner', partnerSchema);

// --- 4. LOGIN SESSION ---
app.use(session({
    secret: 'business-secret-key',
    resave: false,
    saveUninitialized: true
}));

const USERS = {
    'admin': { pass: 'admin123', role: 'admin' },
    'partner': { pass: 'partner2024', role: 'partner' }
};

// --- 5. API ROUTES ---

// Login
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = USERS[username];
    if (user && user.pass === password) {
        req.session.user = { username, role: user.role };
        res.json({ success: true, role: user.role });
    } else {
        res.status(401).json({ success: false, message: 'ভুল ইউজারনেম বা পাসওয়ার্ড' });
    }
});

app.get('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/session', (req, res) => {
    if (req.session.user) res.json({ loggedIn: true, role: req.session.user.role });
    else res.json({ loggedIn: false });
});

// Middlewares
function requireLogin(req, res, next) {
    if (req.session.user) next();
    else res.status(401).json({ error: 'Unauthorized' });
}
function requireAdmin(req, res, next) {
    if (req.session.user && req.session.user.role === 'admin') next();
    else res.status(403).json({ error: 'Only Admin Allowed' });
}

// Expenses
app.post('/api/expense', requireAdmin, async (req, res) => {
    const { date, category, amount, description } = req.body;
    await Expense.create({
        date, category, description,
        amount: encrypt(amount)
    });
    res.json({ message: 'Saved' });
});

app.get('/api/expense', requireLogin, async (req, res) => {
    const expenses = await Expense.find().sort({_id: -1});
    const data = expenses.map(r => ({
        date: r.date,
        category: r.category,
        description: r.description,
        amount: decrypt(r.amount)
    }));
    res.json(data);
});

// Partners (Update & View)
app.post('/api/partner-update', requireAdmin, async (req, res) => {
    const { name, given, due } = req.body;
    await Partner.findOneAndUpdate({ name: name }, {
        given: encrypt(given),
        due: encrypt(due)
    });
    res.json({ message: 'Updated' });
});

app.get('/api/partner', requireLogin, async (req, res) => {
    let partners = await Partner.find();
    // যদি ডাটাবেস খালি থাকে, প্রথমবার পার্টনার তৈরি হবে
    if (partners.length === 0) {
        const names = ['Sona', 'Arindam', 'Ujjal', 'Sagar'];
        for (const name of names) {
            await Partner.create({ name, given: encrypt('0'), due: encrypt('0') });
        }
        partners = await Partner.find();
    }
    
    const data = partners.map(r => ({
        name: r.name,
        given: decrypt(r.given),
        due: decrypt(r.due)
    }));
    res.json(data);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));