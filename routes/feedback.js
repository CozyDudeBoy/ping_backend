// routes/feedback.js
const express = require("express");
const db = require("../db");
const jwt = require("jsonwebtoken");

const router = express.Router();
const JWT_SECRET = "ping_secret_key";

// ✅ Bearer 토큰 인증
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "토큰 없음" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "토큰 형식 오류" });

  try {
    req.user = jwt.verify(token, JWT_SECRET); // { user_no, ... }
    next();
  } catch (err) {
    return res.status(401).json({ message: "토큰 검증 실패" });
  }
}

/**
 * ✅ GET /api/feedback  (내가 남긴 피드백 리스트)
 * - MyFeedback 페이지에서 사용
 */
router.get("/", requireAuth, (req, res) => {
  const user_no = req.user.user_no;

  const sql = `
    SELECT
      a.answer_no,
      a.answer_content,
      a.create_datetime AS answer_datetime,
      q.pin_no,
      q.question_content,
      q.post_no,
      p.post_title,
      img.image_path
    FROM pin_answers a
    JOIN pin_questions q ON a.pin_no = q.pin_no
    JOIN pin_posts p ON q.post_no = p.post_no
    LEFT JOIN pin_post_images img ON q.image_no = img.image_no
    WHERE a.user_no = ?
    ORDER BY a.answer_no DESC
  `;

  db.query(sql, [user_no], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "마이피드백 조회 실패" });
    }
    return res.json(rows);
  });
});

/**
 * ✅ GET /api/feedback/:answer_no  (내 피드백 상세)
 */
router.get("/:answer_no", requireAuth, (req, res) => {
  const { answer_no } = req.params;
  const user_no = req.user.user_no;

  const sql = `
    SELECT
      a.answer_no,
      a.answer_content,
      a.create_datetime AS answer_datetime,

      q.pin_no,
      q.question_content,
      q.post_no,

      p.post_title,
      p.post_content,

      img.image_path
    FROM pin_answers a
    JOIN pin_questions q ON a.pin_no = q.pin_no
    JOIN pin_posts p ON q.post_no = p.post_no
    LEFT JOIN pin_post_images img ON q.image_no = img.image_no
    WHERE a.answer_no = ? AND a.user_no = ?
    LIMIT 1
  `;

  db.query(sql, [answer_no, user_no], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "피드백 상세 조회 실패" });
    }
    if (!rows.length) return res.status(404).json({ message: "피드백 없음" });
    return res.json(rows[0]);
  });
});

/**
 * ✅ PUT /api/feedback/:answer_no  (내 피드백 수정)
 * body: { answer_content }
 */
router.put("/:answer_no", requireAuth, (req, res) => {
  const { answer_no } = req.params;
  const user_no = req.user.user_no;
  const { answer_content } = req.body;

  if (!answer_content || !answer_content.trim()) {
    return res.status(400).json({ message: "내용을 입력해 주세요." });
  }

  const sql = `
    UPDATE pin_answers
    SET answer_content = ?
    WHERE answer_no = ? AND user_no = ?
  `;

  db.query(sql, [answer_content.trim(), answer_no, user_no], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "피드백 수정 실패" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "수정할 피드백이 없습니다." });
    }
    return res.json({ success: true });
  });
});

/**
 * ✅ DELETE /api/feedback/:answer_no  (내 피드백 삭제)
 */
router.delete("/:answer_no", requireAuth, (req, res) => {
  const { answer_no } = req.params;
  const user_no = req.user.user_no;

  const sql = `
    DELETE FROM pin_answers
    WHERE answer_no = ? AND user_no = ?
  `;

  db.query(sql, [answer_no, user_no], (err, result) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "피드백 삭제 실패" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "삭제할 피드백이 없습니다." });
    }
    return res.json({ success: true });
  });
});

module.exports = router;
