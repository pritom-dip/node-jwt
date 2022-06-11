const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

const users = [];
const posts = [
    {
        username: "pritom",
        title: "post 1",
    },
    {
        username: "Dip",
        title: "post 2",
    },
];

app.get("/posts", authenticateToken, (req, res) => {
    const userPosts = posts.filter(post => post.username === req?.user?.name);
    res.status(200).json(userPosts);
});

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];
    if (!token) return res.status(401).send("Unauthrized");
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).send("token is not valid");
        req.user = user;
    });

    next();
}

app.listen(3002, () => console.log("running"));
