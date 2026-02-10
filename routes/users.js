const express = require("express");
const db = require("../db");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const path = require("path");
const multer = require("multer");
const fs = require("fs");

// uploads 폴더 없으면 생성
const uploadDir = path.join(__dirname, "..", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    const safeName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, safeName);
  },
});

const fileFilter = (req, file, cb) => {
  if (!file.mimetype.startsWith("image/")) {
    return cb(new Error("이미지 파일만 업로드 가능합니다."), false);
  }
  cb(null, true);
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
});

const router = express.Router();
const JWT_SECRET = "ping_secret_key";

/**
 * 인증 미들웨어 (이 파일 안에서만 사용)
 * - 1순위: Authorization: Bearer <token>
 * - 2순위: cookie token (req.cookies.token)  ← cookie-parser 쓰는 경우
 */
function auth(req, res, next) {
  const authHeader = req.headers.authorization;

  // Bearer 토큰
  if (authHeader?.startsWith("Bearer ")) {
    const token = authHeader.split(" ")[1];
    try {
      req.user = jwt.verify(token, JWT_SECRET);
      return next();
    } catch (e) {
      return res.status(401).json({ message: "토큰 검증 실패" });
    }
  }

  // 쿠키 토큰 (선택)
  const tokenFromCookie = req.cookies?.token;
  if (tokenFromCookie) {
    try {
      req.user = jwt.verify(tokenFromCookie, JWT_SECRET);
      return next();
    } catch (e) {
      return res.status(401).json({ message: "토큰 검증 실패" });
    }
  }

  return res.status(401).json({ message: "로그인 필요" });
}

/**
 * GET /users/me
 * - pin_users에서 내 정보 조회
 */
router.get("/me", auth, (req, res) => {
  const userNo = req.user.user_no;

  const sql = `
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
    LIMIT 1
  `;

  db.query(sql, [userNo], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "DB 오류" });
    }
    if (!rows.length) {
      return res.status(404).json({ message: "사용자를 찾을 수 없음" });
    }
    return res.json(rows[0]);
  });
});

/**
 * PUT /users/profile
 * body:
 *  - user_nickname (필수)
 *  - user_intro (옵션)
 *  - user_grade (옵션: GENERAL/BASIC/PRO)
 *  - current_pw, new_pw (비번 변경 시만)
 */
router.put("/profile", auth, async (req, res) => {
  const userNo = req.user.user_no;
  const { user_nickname, user_intro, user_grade, current_pw, new_pw } = req.body;

  if (!user_nickname?.trim()) {
    return res.status(400).json({ message: "닉네임은 필수입니다." });
  }

  const grade = ["GENERAL", "BASIC", "PRO"].includes(user_grade)
    ? user_grade
    : "GENERAL";

  // 1) 기본 프로필 업데이트
  const updateSql = `
    UPDATE pin_users
    SET user_nickname = ?,
        user_intro = ?,
        user_grade = ?
    WHERE user_no = ?
  `;

  db.query(updateSql, [user_nickname.trim(), user_intro || "", grade, userNo], async (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "프로필 수정 실패" });
    }

    // 2) 비밀번호 변경 요청이 없으면 종료
    if (!new_pw) {
      return res.json({ success: true });
    }

    // 3) 비밀번호 변경 로직
    if (!current_pw) {
      return res.status(400).json({ message: "현재 비밀번호를 입력해 주세요." });
    }

    const pwSql = `SELECT user_pw FROM pin_users WHERE user_no = ? LIMIT 1`;
    db.query(pwSql, [userNo], async (err2, rows) => {
      if (err2) {
        console.error(err2);
        return res.status(500).json({ message: "비밀번호 조회 실패" });
      }
      if (!rows.length) {
        return res.status(404).json({ message: "사용자를 찾을 수 없음" });
      }

      const hashed = rows[0].user_pw;
      const ok = await bcrypt.compare(current_pw, hashed);
      if (!ok) {
        return res.status(400).json({ message: "현재 비밀번호가 올바르지 않습니다." });
      }

      const newHashed = await bcrypt.hash(new_pw, 10);
      const updatePwSql = `UPDATE pin_users SET user_pw = ? WHERE user_no = ?`;

      db.query(updatePwSql, [newHashed, userNo], (err3) => {
        if (err3) {
          console.error(err3);
          return res.status(500).json({ message: "비밀번호 변경 실패" });
        }
        return res.json({ success: true });
      });
    });
  });
});

/**
 * (옵션) DELETE /users/me  회원탈퇴
 * - 실제 운영은 soft delete 권장하지만, 일단은 예시만.
 */
router.delete("/me", auth, (req, res) => {
  const userNo = req.user.user_no;
  const sql = `DELETE FROM pin_users WHERE user_no = ?`;
  db.query(sql, [userNo], (err) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ message: "회원 탈퇴 실패" });
    }
    return res.json({ success: true });
  });
});


/**
* PUT /users/profile/avatar
* form-data:
*   - avatar: (file)
* 응답:
*   { success: true, user_image: "/uploads/파일명.png" }
*/
router.put("/profile/avatar", auth, upload.single("avatar"), (req, res) => {
  const userNo = req.user.user_no;

  if (!req.file) {
    return res.status(400).json({ message: "파일이 없습니다." });
  }

  const savedPath = `/uploads/${req.file.filename}`;

  db.query(
    `UPDATE pin_users SET user_image = ? WHERE user_no = ?`,
    [savedPath, userNo],
    (err) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ message: "아바타 저장 실패" });
      }
      return res.json({ success: true, user_image: savedPath });
    }
  );
});

module.exports = router;
