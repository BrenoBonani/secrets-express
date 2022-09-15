
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const session = require("express-session");
const Flash = require("connect-flash");

const app = express();

app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(express.static(("views")));
app.use(bodyParser.urlencoded({extended: true}));
app.use(Flash());


app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: true,
    cookie: {}
  }));

module.exports = app;