import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';
import { user as User } from './model/user.model.js';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import { v2 as cloudinary } from 'cloudinary';
import nodemailer from 'nodemailer';


const app = express();
const upload = multer();

app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

mongoose.connect("mongodb://127.0.0.1:27017/Auth");

app.set("views", path.join(__dirname, "views"));
app.set('view engine', 'ejs');

cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
  api_key: process.env.CLOUD_API_KEY,
  api_secret: process.env.CLOUD_API_SECRET,
})

const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL,
      pass: process.env.APP_PASS,
    },
  });

  const sendEmail = async (to, subject, html) => {
    await transporter.sendMail({
      from: `"Auth App" ${process.env.GMAIL} ` ,
      to,
      subject,
      html,
    });
  };



// JWT Middleware
const authenticate = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.redirect("/login");

    try {
        const decoded = jwt.verify(token, "secret");
        req.user = decoded;
        next();
    } catch (err) {
        return res.redirect("/login");
    }
};

app.get('/', (req, res) => {
    try {
        res.render("index");
    } catch (error) {
        console.log(error);
    }
});

app.get("/login", (req, res) => {
    try {
        res.render("login");
    } catch (error) {
        console.log(error);
    }
});

app.get("/profile", authenticate, async (req, res) => {
    try {
        const loggedInUser = await User.findById(req.user.userId);
        res.render("profile", { user: loggedInUser });
    } catch (error) {
        console.log(error);
        res.redirect("/login");
    }
});

app.post('/signUp', upload.single('image'), async (req, res) => {
    try {
        const { email, name, age, password } = req.body;

        let imageUrl = '';
        if (req.file) {
        const base64 = req.file.buffer.toString("base64");
        const dataUri = `data:${req.file.mimetype};base64,${base64}`;
        const result = await cloudinary.uploader.upload(dataUri, {
        folder: 'User_Profiles'
      });
      imageUrl = result.secure_url;
    }

        const ExistingUser = await User.findOne({ email });
        if (ExistingUser) {
            console.log("User exists! Login.");
            return res.render('login');
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ email, name, age, password: hashedPassword, image: imageUrl });

        await newUser.save();

        const token = jwt.sign({ email: newUser.email, userId: newUser._id }, "secret");
        res.cookie("token", token, { httpOnly: true });

        res.redirect("/profile"); 
;
    } catch (error) {
        console.log(error);
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const ExistingUser = await User.findOne({ email });

        if (!ExistingUser) {
            return res.status(404).send("User Does Not Exist");
        }

        const isMatch = await bcrypt.compare(password, ExistingUser.password);
        if (!isMatch) return res.redirect("/login");

        const token = jwt.sign({ email: ExistingUser.email, userId: ExistingUser._id }, "secret");

        res.cookie("token", token, {
            httpOnly: true,
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        });

        res.redirect("/profile");
    } catch (error) {
        console.log(error);
    }
});

app.get('/logout', (req,res) => {
    res.clearCookie("token");
    res.redirect('/login')
})



app.get('/forgot-password', (req, res) => {
    res.render('forgot'); 
  });
  
  app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
  
    if (!user) return res.send("User not found");
  
    const token = jwt.sign({ email: user.email }, "reset-secret", { expiresIn: "15m" });
  
    const resetLink = `http://localhost:3000/reset-password/${token}`;
  
    await sendEmail(email, "Password Reset", `<a href="${resetLink}">Reset Password</a>`);
    res.send("Password reset link sent!");
  });
  
  app.get('/reset-password/:token', (req, res) => {
    const { token } = req.params;
    res.render('reset', { token }); 
  });
  
  app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;
  
    try {
      const decoded = jwt.verify(token, "reset-secret");
      const hashed = await bcrypt.hash(password, 10);
      await User.findOneAndUpdate({ email: decoded.email }, { password: hashed });
  
      res.redirect('/login');
    } catch (err) {
      console.log(err);
      res.send("Invalid or expired token");
    }
  });
  



app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
