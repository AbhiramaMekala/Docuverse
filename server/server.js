//test
const mongoose = require('mongoose');
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const genAI = new GoogleGenerativeAI('AIzaSyCC-_rjwuF1Ll38-ZDcw61ne0ytkcuHhIg'); // Replace with your actual key



const app = express();

app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(express.json());

app.use(session({
    secret: 'yourSecretKey',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }
}));


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

mongoose.connect('mongodb://localhost:27017/db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("MongoDB Error:", err));

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});
const user = mongoose.model('User', userSchema);

const fileSchema = new mongoose.Schema({
    userEmail: String,
    userName: String,
    originalname: String,
    filename: String,
    type: String,
    size: Number,
    uploadDate: { type: Date, default: Date.now }
});



const File = mongoose.model('File', fileSchema);

const pdfKnowledgeSchema = new mongoose.Schema({
    userEmail: String,
    fileId: mongoose.Schema.Types.ObjectId,
    content: String
});
const PdfKnowledge = mongoose.model('PdfKnowledge', pdfKnowledgeSchema);

const FILE_UPLOAD_PATH = path.join(__dirname, '../uploads');
app.use('/uploads', express.static(FILE_UPLOAD_PATH));

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const userFolder = path.join(FILE_UPLOAD_PATH, req.session.user.email);
        fs.mkdirSync(userFolder, { recursive: true });
        cb(null, userFolder);
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage });

app.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
});

function isAuthenticated(req, res, next) {
    if (req.session.user) return next();
    res.redirect('/login');
}

app.get('/', (req, res) => res.render('home'));

app.get('/home', (req, res) => {
    const username = req.session.user ? req.session.user.name : "Guest";
    res.render('home', { error: null, name: username });
});

app.get('/login', (req, res) => res.render('login', { error: null }));
app.get('/files', isAuthenticated, async (req, res) => {
    const files = await File.find({ userEmail: req.session.user.email });

    const MAX_STORAGE = 5 * 1024 * 1024 * 1024; // 5GB
    const usage = { pdf: 0, docs: 0, ppts: 0, photos: 0, videos: 0, others: 0, total: 0, free: 0 };

    files.forEach(file => {
        const ext = file.originalname.toLowerCase();
        if (file.type.includes("pdf")) usage.pdf += file.size;
        else if (file.type.includes("word") || ext.endsWith(".docx") || ext.endsWith(".txt")) usage.docs += file.size;
        else if (ext.endsWith(".ppt") || ext.endsWith(".pptx")) usage.ppts += file.size;
        else if (file.type.startsWith("image/")) usage.photos += file.size;
        else if (file.type.startsWith("video/")) usage.videos += file.size;
        else usage.others += file.size;
    });

    usage.total = usage.pdf + usage.docs + usage.ppts + usage.photos + usage.videos + usage.others;
    usage.free = MAX_STORAGE - usage.total;

    const getWidthClass = (val) => {
        const percent = ((val / MAX_STORAGE) * 100).toFixed(2);
        return `w-[${percent}%]`;
    };

    const widthClasses = {
        pdf: getWidthClass(usage.pdf + usage.docs + usage.others),
        ppts: getWidthClass(usage.ppts),
        media: getWidthClass(usage.photos + usage.videos),
        free: getWidthClass(usage.free)
    };

    res.render('files', {
        error: null,
        name: req.session.user.name,
        files,
        usage,
        maxStorage: MAX_STORAGE,
        widthClasses
    });
});


app.get('/aichat', isAuthenticated, (req, res) => {
    res.render('aichat', {
        error: null,
        chatHistory: req.session.chatHistory || [],
        hasStartedChat: req.session.chatHistory && req.session.chatHistory.length > 0
    });
});


app.get('/signup', (req, res) => res.render('signup', { error: null }));

app.get('/afterlogin', isAuthenticated, async (req, res) => {
    const userEmail = req.session.user.email;
    const query = req.query.q ? req.query.q.trim() : "";

    let files = await File.find({ userEmail });

    if (query) {
        files = files.filter(file =>
            file.originalname.toLowerCase().includes(query.toLowerCase())
        );
    }

    const MAX_STORAGE = 5 * 1024 * 1024 * 1024; // 5GB
    const usage = {
        pdf: 0, docs: 0, ppts: 0, photos: 0, videos: 0, others: 0, total: 0, free: 0
    };

    files.forEach(file => {
        const type = file.type || "";
        const name = file.originalname.toLowerCase();
        const size = file.size;

        if (type.includes("pdf")) usage.pdf += size;
        else if (type.includes("word") || name.endsWith(".doc") || name.endsWith(".docx")) usage.docs += size;
        else if (name.endsWith(".ppt") || name.endsWith(".pptx")) usage.ppts += size;
        else if (type.startsWith("image/")) usage.photos += size;
        else if (type.startsWith("video/")) usage.videos += size;
        else usage.others += size;

        usage.total += size;
    });

    usage.free = MAX_STORAGE - usage.total;

    const usageData = {
        "PDF & Docs": usage.pdf + usage.docs + usage.others,
        "PPTX Files": usage.ppts,
        "Media Files": usage.photos + usage.videos,
        "Free Space": usage.free
    };

    // ✅ FIX: Send userName to the EJS file
    res.render('afterlogin', {
        name: req.session.user.name,
        files,
        usage,
        maxStorage: MAX_STORAGE,
        usageData,
        query
    });
});

app.post('/delete/:id', isAuthenticated, async (req, res) => {
    const fileId = req.params.id;

    try {
        const file = await File.findById(fileId);
        if (!file || file.userEmail !== req.session.user.email) {
            return res.status(403).send('Unauthorized');
        }

        const filePath = path.join(FILE_UPLOAD_PATH, file.userEmail, file.filename);

        // Delete physical file
        fs.unlink(filePath, async (err) => {
            if (err) console.error("File deletion error:", err);
        });

        // Delete from both collections
        await File.deleteOne({ _id: fileId });
        await PdfKnowledge.deleteMany({ fileId });  // <- delete related AI knowledge

        res.redirect('/afterlogin');
    } catch (err) {
        console.error("Deletion error:", err);
        res.status(500).send("Server Error");
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const existing = await user.findOne({ email });
    if (!existing) return res.render('login', { error: "User does not exist" });
    if (existing.password !== password)
        return res.render('login', { error: "Incorrect password" });
    req.session.user = existing;
    res.redirect('/afterlogin');
});

app.post('/signup', async (req, res) => {
    const { name, email, password } = req.body;
    const existing = await user.findOne({ email });

    if (existing)
        return res.render('signup', { error: "User already exists" });

    const newUser = new user({ name, email, password });
    await newUser.save();

    res.render('login', { error: "Signup successful. Please login." });
});



app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.send("Logout failed");
        res.redirect('/home');
    });
});

app.post('/aichat', isAuthenticated, async (req, res) => {
    const userEmail = req.session.user.email;
    const userPrompt = req.body.prompt;

    try {
        const pdfs = await PdfKnowledge.find({ userEmail });
        const combinedText = pdfs.map(doc => doc.content).join("\n").slice(0, 30000);

        const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });

        const chatPrompt = `
You are a helpful assistant. Below is the combined knowledge from uploaded documents:
"""
${combinedText}
"""
Now answer the user's question based on this:
"${userPrompt}"
        `;

        const result = await model.generateContent(chatPrompt);
        const response = await result.response.text();

        // ✅ Store chat history in session
        if (!req.session.chatHistory) req.session.chatHistory = [];
        req.session.chatHistory.push({ prompt: userPrompt, answer: response });

        res.render('aichat', {
            error: null,
            chatHistory: req.session.chatHistory
        });

    } catch (err) {
        const errMsg = err.message.includes("429")
            ? "You've hit the API usage limit. Try again later."
            : "AI processing failed. Please try again.";
        res.render('aichat', {
            error: errMsg,
            chatHistory: req.session.chatHistory || []
        });
    }
});



// change .single('file') to .array('files')
const pdfParse = require('pdf-parse'); // Make sure it's at the top

app.post('/upload', isAuthenticated, upload.array('files'), async (req, res) => {
    const allowedTypes = [
        'application/pdf',
        'application/msword',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    ];

    const userEmail = req.session.user.email;
    const userName = req.session.user.name;
    

    const filePromises = req.files.map(async (file) => {
        const { originalname, mimetype, size, filename } = file;

        // Skip disallowed files
        if (
            !allowedTypes.includes(mimetype) &&
            !mimetype.startsWith('image/') &&
            !mimetype.startsWith('video/')
        ) {
            const filePath = path.join(FILE_UPLOAD_PATH, userEmail, filename);
            fs.unlinkSync(filePath); // delete unwanted file
            return;
        }

        // Save file metadata
        const newFile = new File({
            userEmail,
            userName,
            originalname,
            filename,
            type: mimetype,
            size
        });
        await newFile.save();

        // ✅ If it's a PDF, extract text and save
        if (mimetype === 'application/pdf') {
            const filePath = path.join(FILE_UPLOAD_PATH, userEmail, filename);
            const buffer = fs.readFileSync(filePath);
            const data = await pdfParse(buffer);

            await new PdfKnowledge({
                userEmail,
                fileId: newFile._id,
                content: data.text
            }).save();
        }
    });

    await Promise.all(filePromises);
    res.redirect('/afterlogin');
});




app.listen(3000, () => console.log('Server running on http://localhost:3000'));
