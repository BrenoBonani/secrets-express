 
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const Flash = require("connect-flash");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");


 
const app = express();
 
const port = process.env.PORT || 3000;
 
app.use(express.static("public"));
app.use(express.static(("views")));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");


app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: true,
  cookie: {}
}));

app.use(Flash());
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb+srv://BrenoBonani:963852@cluster0.5qaql.mongodb.net/userDB");


// New User Schema

const userSchema = new mongoose.Schema ({
  googleId: { type: String, unique: true },

  email: String,
  provider: String,
  password: String,
  secret: Array
});

userSchema.plugin(passportLocalMongoose, {usernameField: "username"});
userSchema.plugin(findOrCreate);

// New User Model

const User = mongoose.model("User", userSchema);

// Setting up passport
passport.use(User.createStrategy());


passport.serializeUser(function(user, done) {
  done(null, user);

});
 
passport.deserializeUser(function(user, done) {
  done(null, user);
});

passport.use(new GoogleStrategy({
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET_KEY,
  callbackURL: "http://localhost:3000/auth/google/secrets",
  userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
},
function (accessToken, refreshToken, profile, cb) {
  User.findOrCreate(
    { googleId: profile.id },
    {
      provider: "google",
      email: profile._json.email
    },
    function (err, user) {
        return cb(err, user);
    });
  }
));

/* passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser()); */


// APP GET ROUTE PAGES

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/auth/google", passport.authenticate("google", {

  scope: ["profile", "email"]

}));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login", failureMessage: true }),
  (req, res) => {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
  });

 
app.get("/login", (req, res) => {
  res.render("login", {messages: req.flash()});
});
 
app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/secrets", function(req,res) {
  res.set(
      'Cache-Control', 
      'no-cache, private, no-store, must-revalidate, max-stal e=0, post-check=0, pre-check=0'
  );

  if (req.isAuthenticated()) {
    User.find({ secret: { $ne: null } }, function (err, foundUsers) {
      if (err) {
        console.log(err);
      } else {
        if (foundUsers) {
          res.render('secrets', { usersWithSecrets: foundUsers });
        }
      }
    });
  } else {
    res.redirect('/login');
  }
});

/* 
  if(req.isAuthenticated()) {
      res.render("secrets");        
  } else {
      res.redirect("/login");
  } */


app.get("/failure", (req, res) => {
  res.render("failure");
});


app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

// POST REQUEST FOR SUBMIT

app.post("/submit", (req, res) => {

  const secretPost = req.body.secret;

  User.findById(req.user._id, (err, foundUser) => {
    if (err) {
        console.log(err);
    } else {

        if (foundUser) {
            User.updateOne(
                { _id: req.user._id },
                { $push: { secret: secretPost } },
                (err, result) => {
                    if (err) {
                        console.log(err);
                    } else {
                        res.redirect("/secrets");
                    }
                }
            );
        }
    }
});
});



// APP GET LOGOUT ROUTE
app.get("/logout", (req, res) => {
  
  req.logout((err) => {
    if (err) { 
      console.log(err); 
    }
    res.redirect('/');
  });
});




// POST REQUEST FOR REGISTRATE

app.post("/register", (req, res) => {

  User.register({username: req.body.username}, req.body.password, (err, registeredUser) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
});


});


// POST REQUEST FOR LOGIN
app.post("/login", passport.authenticate('local', { 
  successRedirect: '/secrets',
  failureRedirect: '/failure',
  failureFlash: "Invalid username or password",
  successFlash: "Succesfully logged in." })
);





// LISTEN ROUTE
app.listen(port, () => console.log(`Server started at port: ${port}`)
);





/* 

Depois de criar o template padrão com express, body-parser e ejs. Eu preciso começar a mexer com meu banco de dados, já que vou precisa dele para autenticar os usuários.
Para isso, eu instalo mongoose (npm i mongoose). Feito isso, eu preciso criar o meu novo schema:

const userSchema = {
  email: String,
  password: String
};

Feito isso, eu vou criar um app.post para postar o meu registro de conta. Dessa forma:

app.post("/register", (req, res) => {
  const newUser = new User({
    email: req.body.username,
    password: req.body.password
  });

  newUser.save((err) => {
    if (err) {
      console.log(err);
    } else {
      res.render("secrets")
    }
  });

});

Sendo assim, eu crio o post com o path "/register" e crio uma nova const newUser = new User(). O new User é uma função do próprio mongoose para criar novos documentos. 
Dessa forma, eu posso criar um objeto de javascript e passar o email e password com req.body.name deles que está lá no register.ejs. Feito isso, eu crio o newUser.save()
para salvar os novos que forem inseridos e uso uma condicional em caso de erro. Se não tiver error, res.render("secrets"). Somente depois que o user estiver logado que ele
vai ter acesso a page secrets.

Agora, eu preciso que a pessoa consiga logar, então vou criar outro post request. Para quando o user entra no login page, ele entre com os dados e faça um post request para
a login route. Ficando desse jeito:

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  
});

Eu crio um app.post com "/login" route e duas const com req.body.username e req.body.password. Agora eu preciso usar uma condicional para saber se o email e o password que foi 
entrado, batém com o que o usuário de fato criou. Para isso, eu vou usar o findOne para ver se o email bate com o username que foi criado. Desse jeito:

User.findOne({email: username}, (err, foudUser) => {
  if (err) {
    console.log(err);
  } else {
    if (foundUser) {
      if (foundUser.password === password) {
        res.render("secrets");
      }        
    }
  }
});

Além disso, eu adiciono as condicionais. O primeiro if, passa se que tiver um erro, para postar ele. Caso contrário (else), se tiver (if) um foundUser, então passa para outro if
que se o foundUser.password for igual ao password digitado, então ele vai me deixar ver a page secrets (res.render).

Agora que eu consigo criar uma conta e acessa ela, eu preciso deixar os dados no meu banco de dados mais seguro. Para isso, eu vou começar usando uma criptografia básica, com o
mongoose-encrypttion. Eu instalo ele com "npm i mongoose-encryption". Depois, eu uso const encrypt = require ("mongoose-encryption") e eu preciso modificar o meu Schema criado. 

Agora o Schema criado vai ter const userSchema = new mongoose.Schema. Eu preciso usar esse new mongoose.Schema para modificar ele e embaixo, adicionar:

const secret = "thisisourlittlesecret";

userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

A const secret vai ser igual uma string longa, com uma frase qualquer dentro. Para deixar de forma mais safe para que ninguém veja qual é a frase secreta que vai ligar com o meu secret,
é melhor criar um arquivo .env para que fique guardado todas as minhas keys, passwords e conteúdos que precisam de segurança. Sendo assim, eu crio ela lá, como SECRET_KEY e uso process.env.SECRET_KEY
dentro do {secret: }, assim:

userSchema.plugin(encrypt, { secret: process.env.SECRET_KEY, encryptedFields: ["password"] });

Além disso, eu preciso adicionar um arquivo .gitignore para colocar tudo que eu não quero que vá para o deploy também.

PS: Para add o .env, eu preciso instalar ele com "npm install dotenv --save" e depois eu preciso usar lá no início de tudo do meu app.js o código require('dotenv').config(); Depois disso, eu já posso 
usar tudo normalmente.


===========
INTRO HASH
===========

HASH vai tirar a SECRET_KEY que eu tenho e não vamos mais precisar dela. Dessa forma, eu consigo manter o meu site mais seguro em caso de algum ataque hacker. É quase impossível transformar o hash de volta
em senha. Primeira coisa então é instalar o pacote md5 (hash) com "npm i md5". Depois disso, eu tiro o mongoose.encrypt que eu tava requerendo e apago o plugin que eu tinha criado para encrypt. Então, eu vou 
no meu app.post do register e onde tem req.body.password, eu coloco assim: md5(req.body.password). Dessa forma, vou usar a função do hash md5 para transformar a senha em um hash irreversível.

Porém, tem uma coisa no hash. Quando o usuário cria uma senha, o hash que vai ser gerado para aquela senha sempre será o mesmo. Então, caso outro usuário coloce a mesma senha, vai ser o mesmo hash. Mas é dessa
forma que a gente consegue validar as duas senhas para que o usuário consiga logar. Sendo assim, eu preciso ir lá no app.post do login e também adicionar o md5 no req.body.password.

Agora, vamos colocar o Salting em prática no hash. O Salt, cria vários caracteres aleatórios e esses caracteres são colocados juntos com a senha. Quando ele for passando para o hash function, vai criar uma senha
mais salt aleatório, assim, até senhas simples serão mais complexas e difíceis de se decodificar. Além disso, podemos implementar o salt rounds, que é a cada rodada você pega o hash gerado e coloca mais um salt 
aleatório. Sendo assim, para cada aumento de salt rounds, o tempo que leva para decodificar a sua senha dobra. Então, vamos instalar bcrypt com 

Depois de instalar, agora eu vou tirar o require de md5 lá no começo do meu código e substituir pelo do bcrypt. const bcrypt = require("bcrypt"); lá no início do código. Depois, eu preciso colocar o saltRounds, 
dessa forma: const saltRounds = 10; e depois eu preciso usar:

bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    // Store hash in your password DB.
});

Dentro do meu app.post("/register"). Depois, eu preciso mudar dentro do meu const newUser, o password para password: hash. Dessa forma, a função do bcrypt.hash vai passar o passward que for entrado pelo usuário 
pelo req.body.password, depois vai usar o saltRounds para colocar os números aleatórios e vai chamar uma callback, que vai passar o hash para dentro do password lá no const newUser. Depois disso tudo, vai salvar 
dentro do meu database.

Depois, para que o user consiga logar, eu preciso fazer o check no app.post("/login"). Para isso, o próprio doc do bcrypt no npm explica como. É preciso:

bcrypt.compare(myPlaintextPassword, hash, function(err, result) {
    // result == true
});

É preciso passar essa função de compare dentro do meu if statement no app.post("/login"). Dessa forma:

app.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  User.findOne({email: username}, (err, foundUser) => {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
      bcrypt.compare(password, foundUser.password, function(err, result) {
        if (result === true) {
          res.render("secrets");
        }
      });   
      }
    }
  });
});

O que ele vai fazer, é comparar a password que temos na const password com a senha criada pelo usuário, que o findOne vai achar e passar para o foundUser. Depois, eu preciso criar mais um statement, para checar
se o resultado foi verdadeiro e poder passar o res.render.



========================================
COOKIES & SESSIONS (PASSPORT NODEJS)
========================================

Primeiramente, vou comentar sobre os cookies, que são tags que ficam grudados ao nosso navegador quando entramos em alguma página na internet. Por exemplo, quando entramos na amazon e colocamos algo no carrinho. Ao
sair da Amazon, o próprio servidor dela aloja os cookies no nosso navegador e geram um ID para a gente. Sendo assim, quando entrarmos de novo na Amazon e fizermos um get request para abrir ele no nosso navegador, vai 
voltar o nosso usuário logado e com o que estavamos pesquisando já. Dessa forma, com os cookies, é possível indentificar o que o usuário está pesquisando, bem como, redirecionar ads em outros sites também. 

Para começar, eu preciso isntalar 4 packages. express-session, passport, passport-local, passport-local-mongoose usando npm install. Depois, eu preciso apagar todos os require de bcrypt que eu estava usando. Depois, eu 
apago todo os meus códigos dentro do app.post de login e de register. Agora, eu vou passar o hash, salting e todo o resto usando os pacotes que eu instalei. Agora, primeira coisa é dar require no express-session, passport
e passport-local-mongoose. Depois disso, é importante colocar esse código em cima do meu código connect.mongoose:

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false,
  cookie: { secure: true }
}));

app.use(passport.initialize());
app.use(passport.session());

Primeiro, o app.use(session) com a minha secret que vai ser uma frase (uma string). Depois eu coloco resave e save em false. Depois, eu preciso usar app.use duas vezes, uma para iniciar o pacote passport e outra para 
dar setup na session, para que possamos usar ela também. Agora, eu preciso dar setup no último pacote que é o passportlocalmongoose. Para adiciona-lo, eu preciso adicionar no meu mongoose schema que eu criei, um plugin:

User.plugin(passportLocalMongoose);

Antes do .plugin, eu preciso especificar a const do meu schema que eu criei, no caso, vai ser userSchema. Esse pacote vai ser responsável por fazer o hash e o salts nas senhas que foram criadas e salvar os usuários no meu 
banco de dados. Agora eu dei setup nele, eu preciso usa-lo. Embaixo do meu mongoose model criado, eu vou colocar os códigos necessários embaixo dele, que serão:

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


Isso vai permitir que eu consiga autenticar o usuário. Além disso, o serializer é apenas necessário quando eu estou usando sessions. Ele vai permitir que seja criado o cookie e que fique armazenado dentre dele as indentificações
do nosso usuários. Depois, o deserializer vai permitir com que esse cookie seja quebrado, acessando as indentificações lá dentro e permitindo a autenticação do usuário, bem como, que mais funções possam acontecer com base nisso.

Agora, depois que eu dei setup em tudo. Eu preciso voltar no meu app.post do login e do register para fazer eles voltarem a funcionar. Para isso, eu vou usar o pacote do passportlocalmongoose. Isso vai me permitir autenticar os
usuários. Então, primeiramente, lá no app.post("/register") eu vou digitar:

User.register({username: req.body.username}, req.body.password, (err, registeredUser) => {
    if (err) {
      console.log(err);
      res.redirect("/register");
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      })
    }
});


Então, o primeiro parametro que eu passo, é um JS Object com o username: req.body.username. Ou seja, o que o usuário entrar de username, vou conseguir acessar. O segundo parametro, é o password que o usuário quer registrar. Dessa
forma, eu passo req.body.password. Por fim, eu passo uma callback para caso de error, se não, vai me retornar o novo usuário criado (registeredUser). Se tiver error, vai retornar para o register page para o usuário tentar de novo.

Mas caso, não tenha error. O else vai autenticar o nosso novo usuário usando passport.authenticate("local"). Depois, se tiver tudo certo, vai passar o req, res e a callback. Tendo sucesso nessa parte, vai ser possível verificar o 
cookie do login atual, para checar se continuam logados ou não. Feito isso, vamos redirecionar para a rota do secrets. 

Eu redireciono no ("/secrets") para que eu possa criar uma nova rota, agora para o secrets em si. Dessa forma, se o usuário já estiver logado, ele vai ser redirecionado para a secrets page direto. Mas caso ele não esteja, então ele
vai ser direcionado a page de login. Vai ficar assim:

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login")
  }
});

Ou seja, se o usuário já estiver logado, usando req.isAuthenticated(), que é uma função do passport. Ele vai checar se o nosso usuário está logado. Se estiver, vai redirecionar para o secrets, se não, vamos ter que logar. Mas para
logar, também preciso setar de novo o login route. Dessa forma, vai ficar assim:

app.post("/login", (req, res) => {

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err) {
    if (err) { 
      console.log(err); 
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});


Primeiro, vou criar uma nova const User, para passar o model que eu já criei, com username e password na hora que o usuário entrar e eu conseguir ter acesso a ele. Em seguida, vou usar uma função do passport também, que é req.login.
Dentro dela, vou ter o parametro user (que é o nosso usuário) e uma callback para error. Se (if) tiver error, vamos mostrar no terminal. Se não (else), vou usar o mesmo passport.authenticate("local") para autenticar o usuário e redirecionar
ele para a página de secrets.

Depois que o usuário estiver logado, eu vou enviar um cookie para o browser, para que ele segure a informação do usuário logado enquanto ele estiver com a página aberta.

Agora, eu preciso desautorizar o meu usuário para que ele consiga deslogar. Para isso, eu começo criando a rota, com app.get("/logout"):

app.get("/logout", (req, res) => {

   req.logout((err) => {
     if (err) {
       console.log(err);
     }
     res.redirect('/');
   });
});

Com req.logout (outra função do passport), é possível desautorizar o usuário e deslogar ele, redirecionando para a root route.



===================
THIRD PARTY OAuth
===================

O third party OAuth é um open standard autorization (um padrão de autorização baseada em token). 
O legal de usar OAuth, é que ele é pode acessar outros leveis. Por exemplo, se eu estou logando no meu site pelo facebook ou gmail, eu posso pedir para acessar outros dados além do email e o profile name, mas eu poderia pegar a lista de amigos, os
interesses que o usuário tem seguindo tais páginas e etc.

Ele permite read/write + read access. Isso quer dizer, além de poder acessar as informações anteriores, podemos também pedir permissões para postar no facebook ou no twitter quando o user estiver logado por eles. E por fim, o OAuth permite desautorizar
usar o login de outras plataformas de forma mais fácil.

Primeira coisa é entrar no doc e ir na parte de strategies e escolher o mais recente para google. Depois, é entrar no doc e na parte de login com google e ir para o google devs para começar a dar setup nas keys para usar. Criado lá no google devs, eu tenho
duas keys (CLIENT_ID e CLINET_SECRET_KEY). Feito isso, eu preciso dar require no passport-google e usar passport.use para dar setup nele. Assim:

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET_KEY,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


Dentro do passport.use eu vou ter o meu client key e cliente secret que estão lá no meu .env e a callbackURL que por enquanto vai ser direcionada ao localhost. Em baixo, temos uma função, dentro dela tem um accessToken (token de acesso), que é o que permite obter
os dados relacionados ao usuário, o que nos permite acessar os dados do usuário por mais tempo. Temos o profile, que tem o email, o id e os dados que eu quero. E finalmente, eu uso no User.find os dados que recebemos de volta, assim esse pseudo-code vai achar ou criar 
um usuário de acordo com o ID no meu banco de dados.

Agora, eu tenho dois botões para que o usuário possa logar ou registrar com o seu gmail (um no register.ejs e outro no login.ejs). Agora, os meus botões tem href="/auth/google", mas para esse href funcionar, eu preciso setar o path primeiro. Para isso, eu vou lá no meu 
Route pages (tá comentado no início do código) e abaixo do meu app.get("/"), eu vou criar outro app.get("/auth/google"). Dentro dele, eu vou inserir passport.authenticate("google") e passar um escopo, assim:


app.get("/auth/google", (req, res) => {
  passport.authenticate("google", { scope: ['profile'] });
});

Basicamente, eu estou falando para o app.get usar passaport para autenticar o usuário pelo parametro google, que é o googleStrategy que eu criei, usando o clientId, profile e etc. Depois que isso começar a rodar, eu preciso colocar a outra parte do código, que vai redi
recionar a gente de volta para o site e para as rotas necessárias. Assim:


app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login", failureMessage: true }),
  (req, res) => {
    // Successful authentication, redirect secrets.
    res.redirect("/secrets");
});

O passport vai autenticar e caso esteja tudo certo, vai redirecionar direto para a secrets page, que vai rodar outro autenticação e logar direto. Caso não, vai voltar para a login route. Lembrar também que eu preciso modificar o passport.serielizer original para o do doc 
do passportjs, pq ele vai colocar no padrão para que a sessions funcione em qualquer outro caso. Além disso, eu preciso modificar o meu Schema e colocar o googleId como unique: true para que seja único e não gere duplicação de key (um error que estava dando).





*/



