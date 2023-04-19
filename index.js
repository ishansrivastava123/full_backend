import express from 'express';
import path from 'path';
import mongoose from 'mongoose';
import cookieParser from 'cookie-parser';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';

mongoose.connect("mongodb://127.0.0.1:27017/", {useNewUrlParser:true, useUnifiedTopology:true}, {dbName: "backend"})
.then(() => console.log("Database Connected!"))
.catch((err) => console.log(err))

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema)

const app = express();

app.use(express.static(path.join(path.resolve(), "public")));
app.use(express.urlencoded());
app.use(cookieParser());
app.set("view engine", "ejs")

const isAuthenticated = async (req, res, next) => {
    const { token } = req.cookies
    if(token) {
        const decoded = jwt.verify(token, "itsSecret")
        console.log("isAuthenticated, decoded: ", decoded);
        req.user = await User.findById(decoded._id)
        next();
    }
    else
        res.render("login");
}

app.get("/", isAuthenticated, (req, res) => {
    res.render("logout", {name: req.user.name});
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.post("/login", async (req, res) => {
    const {email, password} = req.body
    
    let user = await User.findOne({ email })
    
    if(!user) {
        return res.redirect("/register")
    }

    const hashedPass = await bcrypt.hash(password, 10)
    
    const isMatch = await bcrypt.compare(password, user.password)
    if(!isMatch) {
        return res.render("login", {email, msg: "Incorrect Password!"})
    }

    const token = jwt.sign({_id : user._id}, "itsSecret")

    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 300*1000)
    })
    return res.render("logout", {name: user.name})
})

app.post("/register", async (req, res) => {
    
    const {name, email, password} = req.body
    
    let user = await User.findOne({ email });
    if(user) {
        return res.render("login", {msg: "Email already in use!"});
    }

    const hashedPass = await bcrypt.hash(password, 10)

    user = await User.create({name, email, password: hashedPass})

    const token = jwt.sign({_id : user._id}, "itsSecret")

    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + 30*1000)
    })
    return res.render("login")
})

app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now())
    })
    res.redirect("/")
})

app.listen(5000, () => {
    console.log("Server is working");
})