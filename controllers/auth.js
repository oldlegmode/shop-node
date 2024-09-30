const User = require('../models/user');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const { validationResult } = require('express-validator');

let transporter = nodemailer.createTransport({
  host: 'smtp.gmail.com',
  port: 465,
  secure: true,
  auth: {
      user: 'nodet3262@gmail.com',
      pass: 'szdd pkkb xkst uuyf'
  }
});

exports.getLogin = (req, res, next) => {
  let message = req.flash('error');
  
  res.render('auth/login', {
    path: '/login',
    pageTitle: 'Login',
    errorMessage: message.length > 0 ? message[0] : null,
    oldInput: {
      email: '',
      password: ''
    },
    validationErrors: []
  });
};

exports.getSignup = (req, res, next) => {
  let message = req.flash('error');
  res.render('auth/signup', {
    path: '/signup',
    pageTitle: 'Signup',
    errorMessage: message.length > 0 ? message[0] : null,
    oldInput: {
      email: '',
      password: '',
      confirmPassword: ''
    },
    validationErrors: []
  });
};

exports.postLogin = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(422).render('auth/login', {
      path: '/login',
      pageTitle: 'Login',
      errorMessage: errors.array()[0].msg,
      oldInput: { 
        email, 
        password
      },
      validationErrors: errors.array()
    })
  }

  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        req.flash("error", "Invalid email or password.");
        return res.redirect("/login");
      }
      bcrypt
        .compare(password, user.password)
        .then((doMatch) => {
          console.log('doMatch: ', doMatch);
          if (doMatch) {
            req.session.isLoggedIn = true;
            req.session.user = user;
            return req.session.save((err) => {
              console.log(err);
              res.redirect("/");
            });
          }
          req.flash("error", "Invalid email or password.");
          res.redirect("/login");
        })
        .catch((err) => {
          console.log(err);
          res.redirect("/login");
        });
    })
};

exports.postSignup = (req, res, next) => {
  const email = req.body.email;
  const password = req.body.password;
  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    console.log('1 errors: ', errors);
    console.log('1 errors.array(): ', errors.array());
    return res.status(422).render('auth/signup', {
      path: '/signup',
      pageTitle: 'Signup',
      errorMessage: errors.array()[0].msg,
      oldInput: { 
        email: email, 
        password: password, 
        confirmPassword: req.body.confirmPassword
      },
      validationErrors: errors.array()
    })
  }
  
  return bcrypt.hash(password, 12)
    .then((hashedPassword) => {
      const user = new User({
        email,
        password: hashedPassword,
        cart: {items: [] }
      });
      
      return user.save();
    })
    .then((result) => {
      res.redirect('/login');        
      return transporter.sendMail({
        from: 'nodet3262@gmail.com',
        to: email,
        subject: "Welcome to Node-shop!",
        html: "<h1>Success signed up!</h1>",
        text: 'Hello world!'
      });
    })
  .catch(console.log)
};

exports.postLogout = (req, res, next) => {
  req.session.destroy(err => {
    console.log(err);
    res.redirect('/');
  });
};

exports.getReset = (req, res, next) => {
  let message = req.flash('error');
  
  res.render('auth/reset', {
    path: '/reset',
    pageTitle: 'Reset Password',
    errorMessage: message.length > 0 ? message[0] : null
  });
};

exports.postReset = (req, res, next) => {
  bcrypt.genSalt(32, (error, buffer) => {
      if (error) {
        return res.redirect('/reset');
      }
      const token = buffer.toString('hex').replace('/', '');

      User.findOne({email: req.body.email})
        .then(user => {
          if (!user) {
            req.flash('error', 'No account with that email found');
            return res.redirect('/reset');
          }

          user.resetToken = token;
          user.resetTokenExpiration = Date.now() + 3600000;
          return user.save();
        })
        .then(result => {
          return transporter.sendMail({
            from: 'nodet3262@gmail.com',
            to: req.body.email,
            subject: "Password reset",
            html: `
              <p>You requested a password reset</p>
              <p>Click this <a href="http://localhost:3000/reset/${token}">link</a> to set a new password</p> 
            `
          });
        })
        .catch(console.log)
  })
}

exports.getNewPassword = (req, res, next) => {
  const token = req.params.token;
  const now = Date.now();
  User.findOne({
      passwordToken: token, 
      resetTokenExpiration: {$gt: Date.now()}
    })
    .then((user) => {
      if (!user) {
        req.flash('error', 'Do not have user with this email or token');
        return res.redirect('/reset');
      }
      let message = req.flash('error');
  
      res.render('auth/new-password', {
        path: '/new-password',
        pageTitle: 'Set New Password',
        errorMessage: message.length > 0 ? message[0] : null,
        userId: user?._id.toString(),
        passwordToken: token
      });
    })
    .catch(console.log);
};

exports.postNewPassword = (req, res, next) => {
  const newPassword = req.body.password;
  const userId = req.body.userId;
  const passwordToken = req.body.passwordToken;
  let resetUser;

  User.findOne({
    _id: userId,
    passwordToken: passwordToken, 
    resetTokenExpiration: {$gt: Date.now()}
  })
  .then((user) => {
    resetUser = user;
    return bcrypt.hash(newPassword, 12);
  })
  .then(hashedPassword => {
    resetUser.password = hashedPassword;
    resetUser.resetToken = undefined;
    resetUser.resetToken = undefined;
    return resetUser.save();
  })
  .then(() => res.redirect('/login'))
  .catch(console.log)
}