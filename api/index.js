const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

app.use(express.json());


const users = [

    {
        id: 1,
        username: "raj123",
        password: "123",
        isAdmin: true
    },
    {
        id: 2,
        username: "sachin123",
        password: "123",
        isAdmin: false
    }
]

let refreshTokens = [];


//Generating Access Token
const generateAccessToken = (user) => {

    return jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin }, "Access-token-Secret-key", { expiresIn: "5s" });
}

const generateRefreshToken = (user) => {

    return jwt.sign({ id: user.id, username: user.username, isAdmin: user.isAdmin }, "refreshToken-secret-key",{expiresIn:"7d"});
}

app.post("/api/refresh", (req, res) => {


    //Check if token send with request
    //check is token present in refreshTokenArray i.e valid token is sent or not
    //Verify Token and generate new tokens and send to user 

    const refreshToken = req.body.token;

    if (!refreshToken) res.status(403).json("No token found");

    if (!refreshTokens.includes(refreshToken)) res.status(403).json("Invalid Token");


    jwt.verify(refreshToken, "refreshToken-secret-key", (err, payload) => {

        err && console.log(err);
        refreshTokens = refreshTokens.filter((token) => token !== refreshToken);

        const newAccessToken = generateAccessToken(payload);
        const newRefreshToken = generateRefreshToken(payload);
        refreshTokens.push(newRefreshToken);

        res.status(200).json({

            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
        })
    })



})

//login with username and password
app.post("/api/login", (req, res) => {

    const { username, password } = req.body;
    const user = users.find((u) => {

        return u.username == username && u.password == password;
    })

    if (!users.includes(user)) return res.status(403).json("User not found");

    var accessToken = generateAccessToken(user);
    var refreshToken = generateRefreshToken(user);
    refreshTokens.push(refreshToken);

    if (user) res.json({ username: user.username, isAdmin: user.isAdmin, accessToken, refreshToken });
    else res.status(404).json("Username or password is incorrect");


});


//middleware: this will be called before in delete route 
const verify = (req, res, next) => {


    const authHeader = req.headers.authorization;

    if (authHeader) {

        const token = authHeader.split(" ")[1];


        jwt.verify(token, "Access-token-Secret-key", (err, payload) => {

            if (err) return res.status(403).json("Token is invalid");

            req.user = payload;
            next();

        })
    }
    else res.json("No token found");

}

//delete users with Jwt token
app.delete("/api/users/:userId", verify, (req, res) => {


    if (req.user.id == req.params.userId || req.user.isAdmin === true) {
        res.status(200).json("user deleted successfully");
    }
    else {
        res.status(403).json("you are not allowed to delete this user");
    }

})


// logout with Jwt token
app.post("/api/logout", (req, res) => {

    const refreshToken = req.body.token;

    if (!refreshToken || !refreshTokens.includes(refreshToken)) res.status(403).json("Invalid Refresh Token");

    refreshTokens = refreshTokens.filter((token) => { token !== refreshToken });

    res.status(200).json("User logged out successfully");


})


app.listen(5000, () => {
    console.log("listing on port 5000...");

})