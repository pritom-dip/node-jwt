const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
dotenv.config();

const app = express();
app.use(express.json());

const users = [];
let refreshTokenArr = [];

app.get("/users", (req, res) => {
    res.json(users);
});

app.post("/users", async (req, res) => {
    try {
        const salt = await bcrypt.genSalt();
        const hashedPassword = await bcrypt.hash(req.body.password, salt);
        const user = { name: req.body.name, password: hashedPassword };
        users.push(user);
        res.status(201).send();
    } catch (err) {
        res.status(500).send();
    }
});

app.post("/users/login", async (req, res) => {
    const user = users.find(user => user.name === req.body.name);
    if (!user) return res.status(400).send("can not find user");

    try {
        if (await bcrypt.compare(req.body.password, user.password)) {
            const accessToken = generateAccessToken(user);
            const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
            refreshTokenArr.push(refreshToken);
            return res.status(200).json({ token: accessToken, refreshToken, user });
        }
        return res.status(401).send("Unauthorized");
    } catch (err) {
        res.status(500).send();
    }
});

app.post("/token", (req, res) => {
    const refreshToken = req.body.token;
    if (!refreshToken) return res.sendStatus(401);
    if (!refreshTokenArr.includes(refreshToken)) return res.sendStatus(403);

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.sendStatus(400);
        const accessToken = generateAccessToken({ name: user.name });

        return res.status(200).json({ token: accessToken });
    });
});

const generateAccessToken = user => {
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: "30s" });
};

app.listen(3004, () => console.log("running auth"));
