const express = require('express');
const router = express.Router();
const connection = require('../db');

router.get('/', (req, res) => {
  const sql = `
    SELECT g.group_name, c.category_name
    FROM pin_category_groups g
    JOIN pin_categories c
      ON g.group_no = c.group_no
       WHERE c.is_active = 1
    ORDER BY g.group_no, c.category_no
  `;

  connection.query(sql, (err, rows) => {
    if (err) return res.status(500).send(err);

    const result = {};
    rows.forEach(r => {
      if (!result[r.group_name]) result[r.group_name] = [];
      result[r.group_name].push(r.category_name);
    });

    res.json(result);
  });
});

module.exports = router;
