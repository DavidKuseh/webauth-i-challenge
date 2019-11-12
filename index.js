const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const bcrypt = require('bcryptjs')
const session = require('express-session');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

const sessionConfig = {
  name: 'outcomes',
  secret: 'no comment',
  cookie: {
    maxAge: 1000 * 30,
    secure: false,
    httpOnly: true,
  },
  resave: false,
  saveUninitialized: false
};

server.use(helmet());
server.use(express.json());
server.use(cors());
server.use(session(sessionConfig))

server.post('/api/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 11)
  const newUser = {
    username: req.body.username,
    password: hash,
  };

  Users.add(newUser)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login',  (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        req.session.user = user;
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function restricted(req, res, next) {
    if (req.session && req.session.user) {
        next();
      } else {
        res.status(401).json({ message: 'You shall not pass!' });
      }
}

server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    }) 
    .catch(err => res.send(err));
});



const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
