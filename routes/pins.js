// routes/pins.js
const express = require("express");
const db = require("../db");
const jwt = require("jsonwebtoken");

const router = express.Router();
const JWT_SECRET = "ping_secret_key";

/* =========================
   🔐 공통 인증 미들웨어
   ========================= */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "로그인 필요" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "토큰 형식 오류" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ message: "토큰 검증 실패" });
  }
}

/* =================================================
   1️⃣ 핀 질문 생성 (이미 쓰고 있는 부분)
   POST /api/pins
   ================================================= */
router.post("/", requireAuth, (req, res) => {
  const { postNo, imageNo, x, y, question, issue } = req.body;
  const userNo = req.user.user_no;

  if (!postNo || !imageNo || x == null || y == null || !question || !issue) {
    return res.status(400).json({ message: "핀 데이터 부족" });
  }

  const insertPinSql = `
    INSERT INTO pin_questions
    (post_no, image_no, user_no, x, y, question_content)
    VALUES (?, ?, ?, ?, ?, ?)
  `;

  db.query(
    insertPinSql,
    [postNo, imageNo, userNo, x, y, question],
    (err, result) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "핀 저장 실패" });
      }

      const pinNo = result.insertId;

      const selectCategorySql = `
        SELECT category_no
        FROM pin_categories
        WHERE category_name = ?
      `;

      db.query(selectCategorySql, [issue], (err, rows) => {
        if (err || rows.length === 0) {
          return res.status(500).json({ message: "카테고리 조회 실패" });
        }

        const categoryNo = rows[0].category_no;

        const insertPinCategorySql = `
          INSERT INTO pin_question_categories
          (pin_no, category_no)
          VALUES (?, ?)
        `;

        db.query(insertPinCategorySql, [pinNo, categoryNo], (err) => {
          if (err) {
            return res
              .status(500)
              .json({ message: "핀 카테고리 저장 실패" });
          }

          res.json({ success: true, pinNo });
        });
      });
    }
  );
});

/* =================================================
   2️⃣ 핀 답변 목록 조회
   GET /api/pins/:pinNo/answers
   ================================================= */
router.get("/:pinNo/answers", (req, res) => {
  const { pinNo } = req.params;

  const sql = `
    SELECT
      a.answer_no,
      a.pin_no,
      a.user_no,               -- 🔥 중요 (내 댓글 판별용)
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
      return res.status(500).json({ message: "답변 조회 실패" });
    }
    res.json(rows);
  });
});

/* =================================================
   3️⃣ 핀 답변 작성
   POST /api/pins/:pinNo/answers
   ================================================= */
router.post('/:pinNo/answers', (req, res) => {
  const { pinNo } = req.params;
  const { content } = req.body;

  if (!content || !content.trim()) {
    return res.status(400).json({ message: '내용이 없습니다.' });
  }

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
    return res.status(401).json({ message: '토큰 검증 실패' });
  }

  const { user_no } = decoded;

  const sql = `
    INSERT INTO pin_answers
    (pin_no, user_no, answer_content)
    VALUES (?, ?, ?)
  `;

  db.query(sql, [pinNo, user_no, content.trim()], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: '답변 작성 실패' });
    }
    res.json({ success: true });
  });
});

module.exports = router;