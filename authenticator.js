import express from 'express';
import mongoose from 'mongoose';
import { v2 as cloudinary } from 'cloudinary';
import multer from 'multer';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import crypto from 'crypto';
import nodemailer from 'nodemailer';
import ratelimit from 'express-rate-limit'
import { type } from 'os';

const forgotPasswordLimiter = ratelimit({
    windowMs: 15 * 60 * 1000,
    max: 2,
    handler: (req, res) => {
        res.status(429).render("forgot.ejs", { message: "To Many Requests, try after 60sec!!!" });
    }
});

dotenv.config()

const app = express();
app.set("view engine", "ejs");

const PORT = process.env.PORT || 3000;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

mongoose.connect(process.env.MONGODB_CONNECT, { dbName: "fakeAuthenticator" }).then((req, res) => {
    console.log("MongoDb is Connected....");
});

const define = mongoose.Schema({
    name: String,
    email: String,
    password: String,
    imgurl: String,
    public_id: String,
    resetToken: String,
    resetTokenExpire: Date,
    lastResetRequest: Date,
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date,
        default: null
    },
});

const otpschema = mongoose.Schema({
    name: String,
    email: String,
    password: String,
    imgbuffer: Buffer,
    imgtype: String,
    otp: String,
    otpMade: {
        type: Date,
        default: Date.now(),
        expires: 300,
    }
});

const fileSchema = new mongoose.Schema({
    user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'yoyo',
        required: true
    },
    url: String,
    public_id: String,
    type: String,           // 'image', 'video', 'raw', etc.
    format: String,         // 'jpg', 'mp4', 'pdf', etc.
    originalName: String,
    uploadedAt: {
        type: Date,
        default: Date.now
    }
});

const File = mongoose.model('File', fileSchema);
const otpModel = mongoose.model('otp', otpschema);
const section = mongoose.model('yoyo', define);

const storage = multer.memoryStorage();
const upload = multer({ storage });

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', async (req, res) => {
    const token = req.cookies.token;
    if (token) {
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        req.aman = await section.findById(decode.id);
        res.render("logout.ejs", { name: req.aman.name, email: req.aman.email, imgurl: req.aman.imgurl, createdAt: req.aman.createdAt, lastLogin: req.aman.lastLogin });
    } else {
        res.render("login.ejs", { error: null });
    }
});

app.get('/register', (req, res) => {
    res.render("register.ejs");
});

app.get('/login', (req, res) => {
    res.render("login.ejs", { error: null });
});

app.post('/register', upload.single('file'), async (req, res) => {
    const name = req.body.name;
    const email = req.body.email;
    const password = req.body.password;

    let user = await section.findOne({ email });
    if (user) return res.render("login.ejs", { error: "user alreay exist" });

    const otp = `${Math.floor(1000 + Math.random() * 9000)}`

    const hashpass = await bcrypt.hash(password, 10);

    await otpModel.findOneAndDelete({ email });

    await otpModel.create({
        name,
        email,
        password: hashpass,
        imgbuffer: req.file.buffer,
        imgtype: req.file.mimetype,
        otp
    });

    const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    await transporter.sendMail({
        to: email,
        subject: "OTP Verification",
        html: `<p> Your OTP is "${otp}", it will expire in 5 miutes </p>`
    });

    res.render("otp.ejs", { email, message: "OTP sent to your email" });
})


app.post('/verify-otp', upload.single('file'), async (req, res) => {
    try {

        const otp = req.body.otp;
        const email = req.body.email;

        const pending = await otpModel.findOne({ email });
        if (!pending) return res.render("login.ejs", { error: "OTP expired or invalid" });

        if (pending.otp !== otp) {
            return res.render("otp.ejs", { email, message: "Invalid OTP" });
        }

        const result = await new Promise((resolve, reject) => {
            cloudinary.uploader.upload_stream(
                { folder: "fakeauthenticator" },
                (error, result) => {
                    if (error) return reject(error);
                    resolve(result);
                }

            ).end(pending.imgbuffer);
        });

        const user = await section.create({
            name: pending.name,
            email: pending.email,
            password: pending.password,
            imgurl: result.secure_url,
            public_id: result.public_id,
        });

        await otpModel.findOneAndDelete({ email });

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
        res.cookie('token', token, {
            httpOnly: true,
            expires: new Date(Date.now() + 60 * 60 * 1000)
        });

        res.redirect('/');

    } catch (error) {
        console.log(error);
        res.status(500).render("login.ejs", { error: "something went wrong" });
    }
});

app.post('/login', async (req, res) => {
    const email = req.body.email;
    const password = req.body.password

    let user = await section.findOne({ email });
    if (!user) return res.redirect('/register');

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.render("login.ejs", { error: "wrong password" });

    user.lastLogin = new Date();
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 5 * 60 * 1000)
    });
    res.redirect('/');
});

app.get('/forgot', (req, res) => {
    res.render("forgot.ejs", { message: null });
});


app.post('/forgot', forgotPasswordLimiter, async (req, res) => {
    try {
        const email = req.body.email;
        const user = await section.findOne({ email });
        if (!user) return res.status(404).render("forgot.ejs", { message: "User Not Found!" })

        const now = Date.now();
        if (user.lastResetRequest && now - user.lastResetRequest < 60 * 1000) {
            return res.status(429).render("forgot.ejs", { message: "Too many requests! Try again after sometimes." });
        }
        user.lastResetRequest = now;

        const token = crypto.randomBytes(32).toString("hex");
        const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

        user.resetToken = hashedToken;
        user.resetTokenExpire = Date.now() + 3600000;

        await user.save();

        const resetURL = `${process.env.BASE_URL}/reset/${token}`
        console.log(resetURL);

        const transporter = nodemailer.createTransport({
            service: "gmail",
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        await transporter.sendMail({
            to: user.email,
            subject: "Password Reset",
            html: `<p> Click <a href="${resetURL}"> Here </a> to reset your password </p>`
        });

        res.send("reset link sent to email");

    } catch (error) {
        res.status(200).send("some error occured");
        console.log(error);
    }
});



app.get('/reset/:token', async (req, res) => {
    const token = req.params.token;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await section.findOne({
        resetToken: hashedToken,
        resetTokenExpire: { $gt: Date.now() }
    });

    if (!user) return res.send("Invailed or expired token");

    res.render('reset.ejs', { token: req.params.token });
});



app.post('/reset/:token', async (req, res) => {
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await section.findOne({
        resetToken: hashedToken,
        resetTokenExpire: { $gt: Date.now() }
    });

    if (!user) return res.send("token expired or invailed");

    const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpire = undefined;
    user.lastResetRequest = undefined;

    await user.save();

    res.send("password changed successfully");
});

app.get('/update', (req, res) => {
    res.render("update.ejs");
});

app.get('/delete', (req, res) => {
    res.render("delete.ejs");
});

app.get('/change', (req, res) => {
    res.render("change.ejs");
});


app.post('/change', upload.single('file'), async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        const user = await section.findById(decode.id);
        if (!user) return res.status(404).send("user not found");

        if (req.file) {

            if (user.public_id) {
                await cloudinary.uploader.destroy(user.public_id);
                console.log("old image deleted");
            }

            const result = await new Promise((resolve, reject) => {
                cloudinary.uploader.upload_stream({ folder: "fakeauthenticator" }, (error, result) => {
                    if (error) {
                        console.log(error)
                        return reject(error)
                    }
                    resolve(result);

                }).end(req.file.buffer);
            });

            user.imgurl = result.secure_url;
            user.public_id = result.public_id;

            await user.save();

            res.redirect('/');

        }
    } catch (error) {
        res.status(500).send("server error");
        console.log(error);
    }

})


app.post('/update', async (req, res) => {

    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        const user = await section.findById(decode.id);
        if (!user) return res.status(404).send("user not found");

        const name = req.body.name;
        user.name = name;
        await user.save();

        res.redirect('/')

    } catch (error) {
        res.status(500).send("server error");
        console.log(error);

    }
})


app.post('/delete', async (req, res) => {

    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        const user = await section.findById(decode.id);
        if (!user) return res.status(404).send("user not found");

        const password = req.body.password;
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.render("login.ejs", { error: "wrong password" });

        if (user.public_id) {
            await cloudinary.uploader.destroy(user.public_id);
        }

        await section.findByIdAndDelete(user._id);

        res.clearCookie('token');
        res.redirect('/');

    } catch (error) {
        res.status(500).send("server error");
        console.log(error);

    }
})

app.get('/files', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET);

        const files = await File.find({ user: decode.id }).sort({ uploadedAt: -1 });

        res.render('files.ejs', { files });
    } catch (error) {
        console.error(error);
        res.status(500).send("Error loading files");
    }
});


app.post('/files', upload.array('files', 10), async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    const decode = jwt.verify(token, process.env.JWT_SECRET);
    const user = await section.findById(decode.id);
    if (!user) return res.status(404).send("User not found");

    for (const file of req.files) {
        const result = await new Promise((resolve, reject) => {
            cloudinary.uploader.upload_stream(
                { folder: "userFiles", resource_type: "auto" },
                (error, result) => {
                    if (error) return reject(error);
                    resolve(result);
                }
            ).end(file.buffer);
        });

        await File.create({
            user: user._id,
            url: result.secure_url,
            public_id: result.public_id,
            type: result.resource_type,
            format: result.format,
            originalName: file.originalname
        });
    }

    res.redirect('/files');
});


app.post('/files/delete/:id', async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');

    const decode = jwt.verify(token, process.env.JWT_SECRET);
    const file = await File.findOne({ _id: req.params.id, user: decode.id });
    if (!file) return res.status(404).send("File not found");

    await cloudinary.uploader.destroy(file.public_id, {
        resource_type: file.type === 'video' || file.type === 'audio' ? file.type : 'image'
    });

    await File.deleteOne({ _id: file._id });

    res.redirect('/files');
});


app.get('/logout', (req, res) => {
    res.cookie('token', null, {
        httpOnly: true,
        expires: new Date(Date.now())
    });
    res.redirect('/');
});

app.listen(PORT, (req, res) => {
    console.log(`Server is running on port ${PORT}`);
});
