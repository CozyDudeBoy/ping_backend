// routes/adminCategories.js
const express = require("express");
const router = express.Router();
const db = require("../db");

/**
 * GET /admin/categories?groupNo=all|number&status=all|active|inactive
 */
router.get("/", (req, res) => {
  const { groupNo = "all", status = "all" } = req.query;

  let sql = `
    SELECT
      c.category_no,
      c.category_name,
      c.group_no,
      g.group_name,
      c.created_at,
      c.is_active,
      (
        SELECT COUNT(*)
        FROM pin_post_categories pc
        WHERE pc.category_no = c.category_no
      ) AS usage_count
    FROM pin_categories c
    JOIN pin_category_groups g ON c.group_no = g.group_no
    WHERE 1=1
  `;

  const params = [];

  if (groupNo !== "all") {
    sql += ` AND c.group_no = ?`;
    params.push(Number(groupNo));
  }

  if (status === "active") {
    sql += ` AND c.is_active = 1`;
  } else if (status === "inactive") {
    sql += ` AND c.is_active = 0`;
  }

  sql += ` ORDER BY c.created_at DESC, c.category_no DESC`;

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error("[adminCategories] 목록 조회 오류:", err);
      return res.status(500).json({ message: "DB 오류(목록 조회)" });
    }
    res.json(rows);
  });
});

/**
 * POST /admin/categories
 * body: { group_no, category_name }
 */
router.post("/", (req, res) => {
  const group_no = Number(req.body.group_no);
  const category_name = (req.body.category_name || "").trim();

  if (!group_no || !category_name) {
    return res
      .status(400)
      .json({ message: "테마(group_no)와 이름(category_name)은 필수입니다." });
  }

  db.query(
    `SELECT 1 FROM pin_categories WHERE group_no = ? AND category_name = ? LIMIT 1`,
    [group_no, category_name],
    (dupErr, dupRows) => {
      if (dupErr) {
        console.error("[adminCategories] 중복 체크 오류:", dupErr);
        return res.status(500).json({ message: "DB 오류(중복 체크)" });
      }
      if (dupRows.length) {
        return res.status(409).json({ message: "이미 존재하는 문제 유형입니다." });
      }

      db.query(
        `
        INSERT INTO pin_categories (group_no, category_name, is_active, created_at)
        VALUES (?, ?, 1, NOW())
        `,
        [group_no, category_name],
        (insErr, result) => {
          if (insErr) {
            console.error("[adminCategories] 추가 오류:", insErr);
            return res.status(500).json({ message: "DB 오류(추가)" });
          }
          res.json({ success: true, category_no: result.insertId });
        }
      );
    }
  );
});

/**
 * PUT /admin/categories/:categoryNo
 * body: { group_no, category_name }
 */
router.put("/:categoryNo", (req, res) => {
  const categoryNo = Number(req.params.categoryNo);
  const group_no = Number(req.body.group_no);
  const category_name = (req.body.category_name || "").trim();

  if (!categoryNo || !group_no || !category_name) {
    return res.status(400).json({ message: "값이 올바르지 않습니다." });
  }

  db.query(
    `SELECT 1 FROM pin_categories WHERE category_no = ? LIMIT 1`,
    [categoryNo],
    (exErr, exRows) => {
      if (exErr) {
        console.error("[adminCategories] 존재 확인 오류:", exErr);
        return res.status(500).json({ message: "DB 오류(존재 확인)" });
      }
      if (!exRows.length) {
        return res.status(404).json({ message: "존재하지 않는 문제 유형입니다." });
      }

      db.query(
        `
        SELECT 1
        FROM pin_categories
        WHERE group_no = ? AND category_name = ? AND category_no <> ?
        LIMIT 1
        `,
        [group_no, category_name, categoryNo],
        (dupErr, dupRows) => {
          if (dupErr) {
            console.error("[adminCategories] 중복 확인 오류:", dupErr);
            return res.status(500).json({ message: "DB 오류(중복 확인)" });
          }
          if (dupRows.length) {
            return res.status(409).json({ message: "이미 존재하는 문제 유형입니다." });
          }

          db.query(
            `UPDATE pin_categories SET group_no = ?, category_name = ? WHERE category_no = ?`,
            [group_no, category_name, categoryNo],
            (upErr) => {
              if (upErr) {
                console.error("[adminCategories] 수정 오류:", upErr);
                return res.status(500).json({ message: "DB 오류(수정)" });
              }
              res.json({ success: true });
            }
          );
        }
      );
    }
  );
});

/**
 * PATCH /admin/categories/:categoryNo/status
 * body: { is_active: 0|1 }
 */
router.patch("/:categoryNo/status", (req, res) => {
  const categoryNo = Number(req.params.categoryNo);
  const is_active = Number(req.body.is_active);

  if (!categoryNo || ![0, 1].includes(is_active)) {
    return res.status(400).json({ message: "값이 올바르지 않습니다." });
  }

  db.query(
    `UPDATE pin_categories SET is_active = ? WHERE category_no = ?`,
    [is_active, categoryNo],
    (err, result) => {
      if (err) {
        console.error("[adminCategories] 상태 변경 오류:", err);
        return res.status(500).json({ message: "DB 오류(상태 변경)" });
      }
      if (!result.affectedRows) {
        return res.status(404).json({ message: "존재하지 않는 문제 유형입니다." });
      }
      res.json({ success: true, is_active });
    }
  );
});

/**
 * POST /admin/categories/merge
 * body: { from_category_no, to_category_no }
 *
 * pin_post_categories 컬럼이 post_no/category_no 임을 반영
 */
router.post("/merge", (req, res) => {
  const from_category_no = Number(req.body.from_category_no);
  const to_category_no = Number(req.body.to_category_no);

  if (!from_category_no || !to_category_no || from_category_no === to_category_no) {
    return res.status(400).json({ message: "병합 값 오류" });
  }

  db.beginTransaction((txErr) => {
    if (txErr) {
      console.error("[adminCategories] 트랜잭션 시작 오류:", txErr);
      return res.status(500).json({ message: "Transaction Error" });
    }

    db.query(
      `
      SELECT category_no, group_no, is_active
      FROM pin_categories
      WHERE category_no IN (?, ?)
      `,
      [from_category_no, to_category_no],
      (selErr, cats) => {
        if (selErr) {
          console.error("[adminCategories] 카테고리 조회 오류:", selErr);
          return db.rollback(() => res.status(500).json({ message: "DB 오류(조회)" }));
        }

        if (!cats || cats.length !== 2) {
          return db.rollback(() => res.status(400).json({ message: "카테고리 오류" }));
        }

        const from = cats.find((c) => c.category_no === from_category_no);
        const to = cats.find((c) => c.category_no === to_category_no);

        if (!from || !to) {
          return db.rollback(() => res.status(400).json({ message: "카테고리 매칭 실패" }));
        }
        if (from.group_no !== to.group_no) {
          return db.rollback(() => res.status(400).json({ message: "같은 테마만 병합 가능" }));
        }
        if (to.is_active !== 1) {
          return db.rollback(() =>
            res.status(400).json({ message: "병합 대상은 활성 상태여야 함" })
          );
        }

        // 1) from -> to 매핑 복사(중복 방지)
        db.query(
          `
          INSERT IGNORE INTO pin_post_categories (post_no, category_no)
          SELECT post_no, ?
          FROM pin_post_categories
          WHERE category_no = ?
          `,
          [to_category_no, from_category_no],
          (insErr) => {
            if (insErr) {
              console.error("[adminCategories] 매핑 이동 오류:", insErr);
              return db.rollback(() => res.status(500).json({ message: "병합 실패(이동)" }));
            }

            // 2) from 매핑 제거
            db.query(
              `DELETE FROM pin_post_categories WHERE category_no = ?`,
              [from_category_no],
              (delErr) => {
                if (delErr) {
                  console.error("[adminCategories] from 매핑 삭제 오류:", delErr);
                  return db.rollback(() => res.status(500).json({ message: "병합 실패(정리)" }));
                }

                // 3) from 비활성화
                db.query(
                  `UPDATE pin_categories SET is_active = 0 WHERE category_no = ?`,
                  [from_category_no],
                  (upErr) => {
                    if (upErr) {
                      console.error("[adminCategories] from 비활성 오류:", upErr);
                      return db.rollback(() =>
                        res.status(500).json({ message: "병합 실패(비활성)" })
                      );
                    }

                    db.commit((cErr) => {
                      if (cErr) {
                        console.error("[adminCategories] commit 오류:", cErr);
                        return db.rollback(() => res.status(500).json({ message: "Commit Error" }));
                      }
                      res.json({ success: true, message: "병합 완료" });
                    });
                  }
                );
              }
            );
          }
        );
      }
    );
  });
});

module.exports = router;
