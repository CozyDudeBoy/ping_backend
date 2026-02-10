const express = require('express');
const multer = require('multer');
const path = require('path');
const db = require('../db');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'ping_secret_key';
const router = express.Router();

/* ===============================
  파일 업로드 설정
=============================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/designs');
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + ext);
  },
});

const upload = multer({ storage });

/* ===============================
  게시물 업로드
=============================== */
router.post(
  '/',
  upload.single('image'),
  (req, res) => {

    /* 🔹 1. 토큰 검증 */
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: '로그인 필요' });
    }

    const token = authHeader.split(' ')[1];
    let decoded;
    try {
      decoded = jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(401).json({ message: '토큰 검증 실패' });
    }

    const userNo = decoded.user_no;

    /* 🔹 2. 요청 데이터 */
    const { title, desc } = req.body;
    const imagePath = `/uploads/designs/${req.file.filename}`;

    // 🔹 카테고리 문자열 배열 파싱
    let issues = [];
    if (req.body.issues) {
      try {
        issues = JSON.parse(req.body.issues);
      } catch (e) {
        console.error('issues 파싱 실패', e);
      }
    }

    /* 🔹 3. 게시물 저장 */
    const postSql = `
      INSERT INTO pin_posts (user_no, post_title, post_content)
      VALUES (?, ?, ?)
    `;

    db.query(postSql, [userNo, title, desc], (err, postResult) => {
      if (err) {
        console.error('게시물 저장 실패', err);
        return res.status(500).json({ success: false });
      }

      const postNo = postResult.insertId;

      /* 🔹 4. 이미지 저장 */
      const imgSql = `
        INSERT INTO pin_post_images (post_no, image_path)
        VALUES (?, ?)
      `;

      db.query(imgSql, [postNo, imagePath], (err, imgResult) => {
        if (err) {
          console.error('이미지 저장 실패', err);
          return res.status(500).json({ success: false });
        }

        const imageNo = imgResult.insertId;

        /* 🔹 5. 카테고리 없는 경우 바로 응답 */
        if (issues.length === 0) {
          return res.json({
            postNo,
            imageNo,
            imagePath,
          });
        }

        /* 🔹 6. category_name → category_no */
        const categorySql = `
          SELECT category_no
          FROM pin_categories
          WHERE category_name IN (?)
        `;

        db.query(categorySql, [issues], (err, rows) => {
          if (err) {
            console.error('카테고리 조회 실패', err);
            return res.status(500).json({ success: false });
          }

          if (rows.length === 0) {
            return res.json({
              postNo,
              imageNo,
              imagePath,
            });
          }

          const values = rows.map(row => [postNo, row.category_no]);

          /* 🔹 7. pin_post_categories 연결 */
          const insertPostCategorySql = `
            INSERT INTO pin_post_categories (post_no, category_no)
            VALUES ?
          `;

          db.query(insertPostCategorySql, [values], (err) => {
            if (err) {
              console.error('post_categories 저장 실패', err);
              return res.status(500).json({ success: false });
            }

            /* ✅ 최종 응답 */
            res.json({
              postNo,
              imageNo,
              imagePath,
            });
          });
        });
      });
    });
  }
);

module.exports = router;