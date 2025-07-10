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

const forgotPasswordLimiter = ratelimit({
    windowMs:15*60*1000,
    max:2,
    handler: (req, res)=>{
        res.status(429).render("forgot.ejs", {message:"to many requests"});
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
    resetToken: String,
    resetTokenExpire: Date,
    lastResetRequest: Date
});

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
        res.render("logout.ejs", { name: req.aman.name, email: req.aman.email, imgurl: req.aman.imgurl });
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

app.post('/register', upload.single('file'), (req, res) => {
    try {
        cloudinary.uploader.upload_stream({ folder: "fakeauthenticator" }, async (error, result) => {
            console.log(result);
            console.log("file uploaded!");

            const hashpass = await bcrypt.hash(req.body.password, 10);
            const obj = {
                name: req.body.name,
                email: req.body.email,
                password: hashpass,
                imgurl: result.secure_url
            }

            let user = await section.findOne({ email: obj.email });
            if (user) return res.render("login.ejs", { error: "user alreay exist" });

            user = await section.create(obj);

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

            res.cookie('token', token, {
                httpOnly: true,
                expires: new Date(Date.now() + 5 * 60 * 1000)
            });

            res.redirect('/');

        }).end(req.file.buffer);
    } catch (error) {
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

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

    res.cookie('token', token, {
        httpOnly: true,
        expires: new Date(Date.now() + 5 * 60 * 1000)
    });
    res.redirect('/');
});

app.get('/forgot', (req, res) => {
    res.render("forgot.ejs", {message:null});
});


app.post('/forgot',forgotPasswordLimiter, async(req, res)=>{
    try {
        const email = req.body.email;
        const user = await section.findOne({email});
        if(!user) return res.status(404).render("forgot.ejs", {message:"User Not Found!"})

        const now = Date.now();
        if(user.lastResetRequest && now - user.lastResetRequest < 60*1000){
            return res.status(429).render("forgot.ejs", {message:"Too many requests! Try again after sometimes."});
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
            service:"gmail",
            auth: {
                user:process.env.EMAIL_USER,
                pass:process.env.EMAIL_PASS
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



app.get('/reset/:token', async(req, res)=>{
    const token = req.params.token;
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await section.findOne({
        resetToken: hashedToken,
        resetTokenExpire: {$gt:Date.now()}
    });

    if(!user) return res.send("Invailed or expired token");

    res.render('reset.ejs', {token: req.params.token});
});



app.post('/reset/:token', async(req, res)=>{
    const hashedToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await section.findOne({
        resetToken: hashedToken,
        resetTokenExpire: {$gt:Date.now()}
    });

    if(!user) return res.send("token expired or invailed");

    const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);

    user.password = hashedPassword;
    user.resetToken = undefined;
    user.resetTokenExpire = undefined;
    user.lastResetRequest = undefined;

    await user.save();

    res.send("password changed successfully");
});



app.get('/logout', (req, res) => {
    res.cookie('token', null, {
        httpOnly: true,
        expires: new Date(Date.now())
    });
    res.redirect('/');
});

app.listen(PORT, (req, res) => {
    console.log("server is running");
});
