const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('./db');
const {
  generateSalt, hashPassword
} = require('./route/generator')


router.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.query(
    "SELECT * FROM admin WHERE username = ?",
    [username],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
        return;
      }

      if (Array.isArray(results) && results.length > 0) {
        const user = results[0];
        const role = 'admin'
        const hashedPassword = hashPassword(password, user.salt, user.pepper);
        if (hashedPassword === user.password) {
          jwt.sign({ username,role }, 'secretkey', { expiresIn: '1d' }, (err, token) => {
            if (err) {
              console.error(err);
              res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
              return;
            }
            res.json({
              token,
              success: true,
              redirectUrl: '/admin/home'
            });
            console.log(token);
          });
        } else {
          res.status(401).json({ success: false, message: 'Username atau password salah!' });
        }
      } else {
        res.status(401).json({ success: false, message: 'Username atau password salah!' });
      }
    }
  );
});

router.post('/register', (req, res) => {
  const { username, password } = req.body;
  const salt = generateSalt();
  const pepper = 'sparta';
  
  const hashedPassword = hashPassword(password, salt, pepper);

  db.query(
    "SELECT username FROM admin WHERE username = ?", [username], (err, results) => {
      if (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
        return;
      } else {
        if (results.length > 0) {
          res.status(400).send("Username Sudah ada");
          return;
        } else {
          db.query(
            "INSERT INTO admin (username, password, salt, pepper) VALUES (?, ?, ?, ?)",
            [username, hashedPassword, salt, pepper],
            (error, results) => {
              if (error) {
                console.error(error);
                res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
                return;
              }
              res.json({ success: true, message: 'Registrasi berhasil' });
            }
          );
        }
      }
    }
  );
});
router.post('/login-user', (req, res) => {
  const { username, password } = req.body;
  db.query(
    "SELECT * FROM siswa WHERE username = ?",
    [username],
    (error, results) => {
      if (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
        return;
      }

      if (Array.isArray(results) && results.length > 0) {
        const user = results[0];
        const role = 'user'
        const hashedPassword = hashPassword(password, user.salt, user.pepper);
        if (hashedPassword === user.password) {
          jwt.sign({ username,role }, 'secretkey', { expiresIn: '1d' }, (err, token) => {
            if (err) {
              console.error(err);
              res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
              return;
            }
            res.json({
              token,
              success: true,
              redirectUrl: `/${user.no_induk}/buku/daftarbuku`
            });
            console.log(token);
          });
        } else {
          res.status(401).json({ success: false, message: 'Username atau password salah!' });
        }
      } else {
        res.status(401).json({ success: false, message: 'Username atau password salah!' });
      }
    }
  );
});

router.post('/register-user', (req, res) => {
  const { username, no_induk, nama, prodi, password } = req.body;
  const salt = generateSalt();
  const pepper = 'sparta';
  
  const hashedPassword = hashPassword(password, salt, pepper);

  db.query(
    "SELECT username FROM siswa WHERE username = ?", [username], (err, results) => {
      if (err) {
        console.error(err);
        res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
        return;
      } else {
        if (results.length > 0) {
          res.status(400).send("Username Sudah ada");
          return;
        } else {
          db.query(
            "INSERT INTO siswa (username, no_induk, nama, prodi, password, salt, pepper) VALUES (?, ?, ?, ?, ?, ?, ?)",
            [username, no_induk, nama, prodi, hashedPassword, salt, pepper],
            (error, results) => {
              if (error) {
                console.error(error);
                res.status(500).json({ success: false, message: 'Terjadi kesalahan pada server' });
                return;
              }
              res.json({ success: true, message: 'Registrasi berhasil' });
            }
          );
        }
      }
    }
  );
});


module.exports = router;
