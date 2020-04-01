require('dotenv').config();
var mongoose = require('mongoose');
mongoose.connect(process.env.JWT_DB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
