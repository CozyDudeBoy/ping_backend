// routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../db');

const router = express.Router();
const SALT_ROUNDS = 10;
const JWT_SECRET = 'ping_secret_key';


  //  회원가입
  //  POST /auth/signup
router.post('/signup', async (req, res) => {
  const {
    user_id,
    user_pw,
    user_nickname,
    user_intro,
    user_grade,
  } = req.body;

  if (!user_id || !user_pw || !user_nickname) {
    return res.status(400).json({
      message: '아이디, 비밀번호, 닉네임은 필수입니다.',
    });
  }

  try {
    db.query(
      'SELECT user_no FROM pin_users WHERE user_id = ?',
      [user_id],
      async (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: 'DB 오류' });
        }

        if (rows.length > 0) {
          return res.status(409).json({ message: '이미 사용 중인 아이디입니다.' });
        }

        const hashedPw = await bcrypt.hash(user_pw, SALT_ROUNDS);

        db.query(
          `
          INSERT INTO pin_users
          (user_id, user_pw, user_nickname, user_intro, user_grade, user_role)
          VALUES (?, ?, ?, ?, ?, 'USER')
          `,
          [
            user_id,
            hashedPw,
            user_nickname,
            user_intro || null,
            user_grade || 'GENERAL',
          ],
          (err2) => {
            if (err2) {
              console.error(err2);
              return res.status(500).json({ message: '회원가입 실패' });
            }

            res.json({ success: true });
          }
        );
      }
    );
  } catch (e) {
    console.error(e);
    res.status(500).json({ message: '서버 오류' });
  }
});


  //  로그인
  //  POST /auth/login
router.post('/login', (req, res) => {
  const { user_id, user_pw } = req.body;

  if (!user_id || !user_pw) {
    return res.status(400).json({
      message: '아이디와 비밀번호를 입력해 주세요.',
    });
  }

  db.query(
    'SELECT * FROM pin_users WHERE user_id = ?',
    [user_id],
    async (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: 'DB 오류' });
      }

      if (rows.length === 0) {
        return res.status(401).json({ message: '아이디 또는 비밀번호 오류' });
      }

      const user = rows[0];
      const isMatch = await bcrypt.compare(user_pw, user.user_pw);

      if (!isMatch) {
        return res.status(401).json({ message: '아이디 또는 비밀번호 오류' });
      }

      const payload = {
        user_no: user.user_no,
        user_role: user.user_role,
        user_grade: user.user_grade,
      };

      const token = jwt.sign(payload, JWT_SECRET, {
        expiresIn: '1d',
      });

      console.log('[LOGIN] token 발급됨');

      res.json({
        token,
        user: {
          user_no: user.user_no,
          user_id: user.user_id,
          user_nickname: user.user_nickname,
          user_grade: user.user_grade,
          user_role: user.user_role,
        },
      });
    }
  );
});


  //  로그인 유지 / 내 정보
  //  GET /auth/me

router.get('/me', (req, res) => {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: '토큰 없음' });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: '토큰 형식 오류' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log('[ME] token 검증 성공:', decoded);

    const { user_no } = decoded;

    db.query(
      `
      SELECT
        user_no,
        user_id,
        user_nickname,
        user_intro,
        user_image,
        user_banner,
        user_grade,
        user_role,
        create_datetime
      FROM pin_users
      WHERE user_no = ?
      `,
      [user_no],
      (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: '회원 조회 실패' });
        }

        if (rows.length === 0) {
          return res.status(404).json({ message: '회원 정보 없음' });
        }

        res.json(rows[0]);
      }
    );
  } catch (err) {
    console.error('[ME] token 검증 실패:', err.message);
    res.status(401).json({ message: '토큰 검증 실패' });
  }
});

module.exports = router;