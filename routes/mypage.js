// routes/mypage.js
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const db = require("../db");

const router = express.Router();

const JWT_SECRET = "ping_secret_key";
const SALT_ROUNDS = 10;

// ======================
// JWT 인증 미들웨어 (Bearer 토큰)
// 로그인 유무
// ======================
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ message: "토큰 없음" });
  }

  const token = authHeader.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "토큰 형식 오류" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; 
    next();
  } catch (err) {
    console.error("[AUTH] token 검증 실패:", err.message);
    return res.status(401).json({ message: "토큰 검증 실패" });
  }
}

// ======================
// 1) 마이페이지용 프로필 조회
// GET /api/mypage
// ======================
router.get("/", requireAuth, (req, res) => {
  const { user_no } = req.user;

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
        return res.status(500).json({ message: "회원 조회 실패" });
      }
      if (rows.length === 0) {
        return res.status(404).json({ message: "회원 정보 없음" });
      }
      return res.json(rows[0]);
    }
  );
});

// ======================
// 2) 프로필 수정 + 비번 변경
// PUT /api/mypage/profile
// ======================
router.put("/profile", requireAuth, async (req, res) => {
  const { user_no } = req.user;

  const {
    user_nickname,
    user_intro,
    user_grade,
    current_pw, 
    new_pw,    
  } = req.body;

  if (!user_nickname || !user_nickname.trim()) {
    return res.status(400).json({ message: "닉네임은 필수입니다." });
  }

  try {
    // 1) 현재 유저 정보 가져오기 (비밀번호 확인)
    db.query(
      "SELECT user_pw FROM pin_users WHERE user_no = ?",
      [user_no],
      async (err, rows) => {
        if (err) {
          console.error(err);
          return res.status(500).json({ message: "DB 오류" });
        }
        if (rows.length === 0) {
          return res.status(404).json({ message: "회원 정보 없음" });
        }

        let newHashedPw = null;

        // 2) 비밀번호 변경 요청이 들어온 경우만 비번 해싱
        if (new_pw) {
          if (!current_pw) {
            return res.status(400).json({ message: "현재 비밀번호를 입력해 주세요." });
          }

          const isMatch = await bcrypt.compare(current_pw, rows[0].user_pw);
          if (!isMatch) {
            return res.status(401).json({ message: "비밀번호가 일치하지 않습니다." });
          }

          newHashedPw = await bcrypt.hash(new_pw, SALT_ROUNDS);
        }

        // 3) 업데이트 쿼리 
        const fields = [];
        const values = [];

        fields.push("user_nickname = ?");
        values.push(user_nickname.trim());

        fields.push("user_intro = ?");
        values.push(user_intro || null);

        fields.push("user_grade = ?");
        values.push(user_grade || "GENERAL");

        if (newHashedPw) {
          fields.push("user_pw = ?");
          values.push(newHashedPw);
        }

        values.push(user_no);

        db.query(
          `
          UPDATE pin_users
          SET ${fields.join(", ")}
          WHERE user_no = ?
          `,
          values,
          (err2) => {
            if (err2) {
              console.error(err2);
              return res.status(500).json({ message: "프로필 수정 실패" });
            }
            return res.json({ success: true });
          }
        );
      }
    );
  } catch (e) {
    console.error(e);
    return res.status(500).json({ message: "서버 오류" });
  }
});

// ======================
// 3) 마이 디자인(내가 쓴 글) 조회 + 썸네일 1장
// GET /api/mypage/designs
// ======================
router.get("/designs", requireAuth, (req, res) => {
  const { user_no } = req.user;
  const limit = Number(req.query.limit || 20);
  const offset = Number(req.query.offset || 0);

  db.query(
    `
    SELECT
      p.post_no,
      p.user_no,
      p.post_title,
      p.post_content,
      p.view_count,
      p.like_count,
      p.dislike_count,
      p.create_datetime,
      (
        SELECT image_path
        FROM pin_post_images
        WHERE post_no = p.post_no
        ORDER BY image_no ASC
        LIMIT 1
      ) AS image_path
    FROM pin_posts p
    WHERE p.user_no = ?
    ORDER BY p.post_no DESC
    LIMIT ? OFFSET ?
    `,
    [user_no, limit, offset],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "마이디자인 조회 실패" });
      }
      return res.json({ items: rows, limit, offset });
    }
  );
});

// ======================
// 4) 마이 피드백(내가 남긴 답변) 조회
// GET /api/mypage/feedback
// ======================
// ======================
// 4) 마이 피드백 (내가 남긴 핀 답변)
// GET /api/mypage/feedback
// ======================
router.get("/feedback", requireAuth, (req, res) => {
  const { user_no } = req.user;

  db.query(
    `
    SELECT
      a.answer_no,
      a.pin_no,
      a.answer_content,
      a.create_datetime AS answer_datetime,

      q.post_no,
      q.image_no,
      q.question_content,

      p.post_title,

      img.image_path
    FROM pin_answers a
    JOIN pin_questions q
      ON a.pin_no = q.pin_no
    JOIN pin_posts p
      ON q.post_no = p.post_no
    JOIN pin_post_images img
      ON q.image_no = img.image_no
    WHERE a.user_no = ?
    ORDER BY a.answer_no DESC
    `,
    [user_no],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "마이피드백 조회 실패" });
      }
      return res.json(rows);
    }
  );
});



module.exports = router;
