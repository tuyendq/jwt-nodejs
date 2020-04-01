// AuthController.js
'use strict';

var VerifyToken = require('./VerifyToken');

var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
router.use(bodyParser.urlencoded({ extended: false}));
router.use(bodyParser.json());
var User = require('../user/User');

var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');


router.post('/register', function(req, res) {
    var hashedPassword = bcrypt.hashSync(req.body.password, 8);

    User.create({
        name: req.body.name,
        email: req.body.email,
        password: hashedPassword
    },
    function (err, user) {
        if (err) return res.status(500).send("There was a problem registering the user.");
        // Create a token
        var token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 86400 // 24 hours
        });
        res.status(200).send({ auth: true, token: token });
    });
});

router.get('/me', function (req, res, next) {
    var token = req.headers['x-access-token'];
    // Return 401 unauthorized error code
    if (!token) return res.status(401).send({ auth: false, message: 'No token provided.'});

    jwt.verify(token, config.secret, function(err, decoded) {
        if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.'});

        // res.status(200).send(decoded);
        User.findById(decoded.id, 
            { password: 0 }, // projection: hide password field
            function (err, user) {
            if (err) return res.status(500).send("There was problem finding user.");
            if (!user) return res.status(400).send("No user found.");

            res.status(200).send(user);
            // next(user);
        });
    });
});

// router.use(function (user, req, res, next) {
//     res.status(200).send(user);
// });

router.post('/login', function (req, res) {
    User.findOne({ email: req.body.email }, function (err, user) {
        if (err) return res.status(500).send('Error on server side.');
        if (!user) return res.status(404).send('No such user found.');

        var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
        if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

        var token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 86400 // 24 hours
        });
        
        res.status(200).send({ auth: true, token: token});

    });
});

router.get('/logout', function(req, res) {
    res.status(200).send({ auth: false, token: null });
});


module.exports = router;