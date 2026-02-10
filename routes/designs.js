const express = require('express');
const router = express.Router();
const db = require('../db');

router.get('/:postNo', (req, res) => {
  const { postNo } = req.params;

  // 1. 게시물
  const postSql = `
    SELECT 
  p.post_no, 
  p.post_title, 
  p.post_content,
  u.user_nickname,
  u.user_image
FROM pin_posts p
JOIN pin_users u ON u.user_no = p.user_no
WHERE p.post_no = ?
  `;

  db.query(postSql, [postNo], (err, postRows) => {
    if (err || postRows.length === 0) {
      return res.status(404).json({ message: '게시물 없음' });
    }

    const post = postRows[0];

    // 2. 이미지
    const imageSql = `
      SELECT image_no, image_path
      FROM pin_post_images
      WHERE post_no = ?
      LIMIT 1
    `;

    db.query(imageSql, [postNo], (err, imageRows) => {
      if (err || imageRows.length === 0) {
        return res.status(404).json({ message: '이미지 없음' });
      }

      const image = imageRows[0];

      // 3. 핀
      const pinSql = `
        SELECT pin_no, x, y, question_content AS question
        FROM pin_questions
        WHERE post_no = ?
      `;

      db.query(pinSql, [postNo], (err, pins) => {
        if (err) return res.status(500).json(err);

        res.json({
          post,
          imageUrl: image.image_path,
          pins,
        });
      });
    });
  });
});

module.exports = router;
