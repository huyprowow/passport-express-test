const express = require("express");
const router = express.Router();
const passport = require("passport");
const LocalStrategy = require("passport-local");
const crypto = require("crypto");
const db = require("../db");

//fetch + verify người dùng
const verify = (username, password, cb) => {
  db.get(
    "SELECT rowid AS id, * FROM users WHERE username = ?",
    [username],
    (err, row) => {
      if (err) {
        return cb(err);
      }
      if (!row) {
        return cb(null, false, { message: "Incorrect username or password." });
      }

      crypto.pbkdf2(
        password,
        row.salt,
        310000,
        32,
        "sha256",
        (err, hashedPassword) => {
          if (err) {
            return cb(err);
          }
          if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
            return cb(null, false, {
              message: "Incorrect username or password.",
            });
          }
          return cb(null, row);
        }
      );
    }
  );
};
//Định cấu hình LocalStrategy để tìm nạp bản ghi người dùng từ cơ sở dữ liệu của ứng dụng
//và xác minh mật khẩu băm được lưu trữ cùng với bản ghi
passport.use(new LocalStrategy(verify));

//quản lý phiên đăng nhập
passport.serializeUser((user, cb) => {
  process.nextTick(() => {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser((user, cb) => {
  process.nextTick(() => cb(null, user));
});

router.get("/login", (req, res, next) => {
  res.render("login");
});

router.post(
  "/login/password",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

router.post("/logout", function (req, res, next) {
  req.logout();
  res.redirect("/");
});

router.get("/signup", function (req, res, next) {
  res.render("signup");
});

//tạo một bản ghi người dùng mới trong cơ sở dữ liệu của ứng dụng,
// lưu trữ tên người dùng và mật khẩu được băm.
router.post("/signup", (req, res, next) => {
  const salt = crypto.randomBytes(16);
  crypto.pbkdf2(
    req.body.password,
    salt,
    310000,
    32,
    "sha256",
    (err, hashedPassword) => {
      if (err) {
        return next(err);
      }
      db.run(
        "INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)",
        [req.body.username, hashedPassword, salt],
        (err) => {
          if (err) {
            return next(err);
          }
          var user = {
            id: this.lastID,
            username: req.body.username,
          };
          req.login(user, (err) => {
            if (err) {
              return next(err);
            }
            res.redirect("/");
          });
        }
      );
    }
  );
});

module.exports = router;
