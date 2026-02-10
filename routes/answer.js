
// 핀 답변 조회 페이지 
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const db = require('../db');
const JWT_SECRET = 'ping_secret_key';

// 핀 답변 조회
router.get('/api/pins/:pinNo/answers', (req, res) => {
  const { pinNo } = req.params;

  const sql = `
    SELECT
      a.answer_no,
      a.pin_no,
      a.user_no, 
      a.answer_content,
      a.create_datetime,
      u.user_nickname
    FROM pin_answers a
    JOIN pin_users u ON a.user_no = u.user_no
    WHERE a.pin_no = ?
    ORDER BY a.create_datetime ASC
  `;

  db.query(sql, [pinNo], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: '답변 조회 실패' });
    }

    res.json(rows);
  });
});

// 핀 답변 작성
router.post('/api/pins/:pinNo/answers', (req, res) => {
  const { pinNo } = req.params;
  const { content } = req.body;

  if (!content) {
    return res.status(400).json({ message: '내용이 없습니다.' });
  }

  // 1️⃣ Authorization 헤더에서 토큰 추출
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: '토큰 없음' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ message: '토큰 형식 오류' });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    console.error('JWT 검증 실패:', err.message);
    return res.status(401).json({ message: '토큰 검증 실패' });
  }

  const { user_no } = decoded;

  // 2️⃣ DB INSERT
  const sql = `
    INSERT INTO pin_answers
    (pin_no, user_no, answer_content)
    VALUES (?, ?, ?)
  `;

  db.query(sql, [pinNo, user_no, content], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: '답변 작성 실패' });
    }

    res.json({ success: true });
  });
});


module.exports = router;