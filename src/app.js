require('dotenv').config();
const express = require("express");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const path = require("path");
const Register = require("./model/register");
const auth = require("./middleware/auth");

const app = express();
const port = process.env.port || 3000;

require("./db/conn");

// Setting up paths and middleware
const static_path = path.join(__dirname, "../public");
const template_path = path.join(__dirname, "../templates/views");
const partials_path = path.join(__dirname, "../templates/partials");

app.use(express.static(static_path));
app.set("view engine", "hbs");
app.set("views", template_path);
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));

// Routes

// Home route
app.get("/", (req, res) => {
    res.render("register");
});

// Registration page
// app.get("/registration", (req, res) => {
//     res.render("registration");
// });

// Login page
app.get("/login", (req, res) => {
    res.render("login");
});

// Register POST route
app.post("/register", async (req, res) => {
    try {
        const password = req.body.password;
        const cpassword = req.body.confirmPassword;

        if (password === cpassword) {
            const newUser = new Register({
                name: req.body.name,
                contact: req.body.contact,
                date: req.body.date,
                prn: req.body.prn,
                password: req.body.password,
                branch: req.body.branch,
                roomReference: req.body.roomReference,
                email: req.body.email,
                preference: req.body.preference,
                confirmPassword: cpassword
            });

            // Generate JWT token and save the user
            const token = await newUser.generateAuthToken();
            res.cookie("jwt", token, {
                expires: new Date(Date.now() + 3000),
                httpOnly: true
            });

            await newUser.save();
            res.status(201).render("login");
        } else {
            res.send("Passwords do not match.");
        }
    } catch (error) {
        res.status(400).send(error);
    }
});

// Login POST route
app.post("/login", async (req, res) => {
    try {
        const email = req.body.email;
        const password = req.body.password;
        const user = await Register.findOne({ email: email });

        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            const token = await user.generateAuthToken();
            res.cookie("jwt", token, {
                expires: new Date(Date.now() + 3600000),
                httpOnly: true
            });
            res.status(201).render("logout", { userName: user.name });
        } else {
            res.send("Invalid password.");
        }
    } catch (error) {
        res.status(400).send("Invalid login details.");
    }
});

// Logout route
app.get("/logout", auth, async (req, res) => {
    try {
        req.user.tokens = [];
        res.clearCookie("jwt");
        await req.user.save();
        res.render("login");
    } catch (error) {
        res.status(500).send(error);
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
