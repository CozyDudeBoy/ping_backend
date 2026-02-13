// routes/admin.js
const express = require("express");
const jwt = require("jsonwebtoken");
const db = require("../db");

const router = express.Router();
const JWT_SECRET = "ping_secret_key"; // auth.js와 동일해야 함

// ✅ ADMIN만 통과
function requireAdmin(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "토큰 없음" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "토큰 형식 오류" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    if (decoded.user_role !== "ADMIN") {
      return res.status(403).json({ message: "ADMIN only" });
    }

    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "토큰 검증 실패" });
  }
}

// ✅ 이 파일의 모든 API는 ADMIN만
router.use(requireAdmin);

/**
 * --------------------------------------------------------------------
 * USERS
 * --------------------------------------------------------------------
 * GET /admin/users  (※ app.use('/api/admin', router)라면 최종: /api/admin/users)
 */
router.get("/users", (req, res) => {
  const sql = `
    SELECT
      u.user_no,
      u.user_id,
      u.user_nickname,
      u.user_intro,
      u.user_grade,
      u.user_role,
      u.create_datetime,
      COUNT(DISTINCT p.post_no)   AS designs,
      COUNT(DISTINCT q.pin_no)    AS pins,
      COUNT(DISTINCT a.answer_no) AS comments
    FROM pin_users u
    LEFT JOIN pin_posts p ON p.user_no = u.user_no
    LEFT JOIN pin_questions q ON q.post_no = p.post_no
    LEFT JOIN pin_answers a ON a.pin_no = q.pin_no
    GROUP BY
      u.user_no, u.user_id, u.user_nickname, u.user_intro, u.user_grade, u.user_role, u.create_datetime
    ORDER BY u.user_no DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("[admin/users] DB 오류:", err);
      return res.status(500).json({ message: "DB 오류" });
    }
    res.json(rows);
  });
});

/**
 * DELETE /admin/users/:id
 * - 유저 완전 삭제 (CASCADE 전제)
 * - 자기 자신 삭제 방지
 */
router.delete("/users/:id", (req, res) => {
  const userNo = Number(req.params.id);
  if (!userNo) return res.status(400).json({ message: "유효하지 않은 사용자 ID" });

  // 자기 자신 삭제 방지
  if (String(req.user.user_no) === String(userNo)) {
    return res.status(403).json({ message: "본인 계정은 삭제할 수 없습니다." });
  }

  db.query("SELECT user_no FROM pin_users WHERE user_no = ?", [userNo], (selErr, rows) => {
    if (selErr) {
      console.error("[admin/users/delete] 조회 실패:", selErr);
      return res.status(500).json({ message: "DB 오류(조회)" });
    }
    if (!rows.length) {
      return res.status(404).json({ message: "존재하지 않는 사용자" });
    }

    db.query("DELETE FROM pin_users WHERE user_no = ?", [userNo], (delErr, result) => {
      if (delErr) {
        console.error("[admin/users/delete] 삭제 실패:", delErr);
        return res.status(500).json({ message: "회원 삭제 실패" });
      }
      if (!result.affectedRows) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }
      res.json({ success: true });
    });
  });
});

/**
 * --------------------------------------------------------------------
 * POSTS (디자인 관리)
 * --------------------------------------------------------------------
 * GET /admin/posts
 */
router.get("/posts", (req, res) => {
  const sql = `
    SELECT
      p.post_no AS id,
      p.post_title AS title,
      p.create_datetime AS createdAt,
      COALESCE(u.user_nickname, u.user_id) AS author,
      COUNT(DISTINCT q.pin_no) AS pins,
      COUNT(DISTINCT a.answer_no) AS comments
    FROM pin_posts p
    LEFT JOIN pin_users u ON p.user_no = u.user_no
    LEFT JOIN pin_questions q ON q.post_no = p.post_no
    LEFT JOIN pin_answers a ON a.pin_no = q.pin_no
    GROUP BY p.post_no, p.post_title, p.create_datetime, u.user_nickname, u.user_id
    ORDER BY p.post_no DESC
  `;

  db.query(sql, (err, rows) => {
    if (err) {
      console.error("[admin/posts] DB 오류:", err);
      return res.status(500).json({ message: "DB 오류" });
    }
    res.json(rows);
  });
});

/**
 * DELETE /admin/posts/:id
 * - 관련 자식 레코드까지 안전하게 삭제
 */
router.delete("/posts/:id", (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ message: "유효하지 않은 id" });

  db.query("SELECT post_no FROM pin_posts WHERE post_no = ?", [id], (selErr, rows) => {
    if (selErr) {
      console.error("[admin/posts/delete] 게시물 조회 실패:", selErr);
      return res.status(500).json({ message: "게시물 조회 실패" });
    }
    if (!rows.length) {
      return res.status(404).json({ message: "대상 게시물을 찾을 수 없습니다." });
    }

    db.beginTransaction((txErr) => {
      if (txErr) {
        console.error("[admin/posts/delete] 트랜잭션 시작 실패:", txErr);
        return res.status(500).json({ message: "트랜잭션 시작 실패" });
      }

      const steps = [
        {
          sql: `
            DELETE a
            FROM pin_answers a
            JOIN pin_questions q ON a.pin_no = q.pin_no
            WHERE q.post_no = ?
          `,
          params: [id],
        },
        { sql: "DELETE FROM pin_questions WHERE post_no = ?", params: [id] },
        { sql: "DELETE FROM pin_post_images WHERE post_no = ?", params: [id] },
        { sql: "DELETE FROM pin_post_categories WHERE post_no = ?", params: [id] },
        { sql: "DELETE FROM pin_posts WHERE post_no = ?", params: [id] },
      ];

      const runStep = (i) => {
        if (i >= steps.length) {
          return db.commit((commitErr) => {
            if (commitErr) {
              console.error("[admin/posts/delete] 커밋 실패:", commitErr);
              return db.rollback(() => res.status(500).json({ message: "커밋 실패" }));
            }
            return res.json({ success: true });
          });
        }

        const { sql, params } = steps[i];
        db.query(sql, params, (qErr, result) => {
          if (qErr) {
            console.error("[admin/posts/delete] 삭제 실패:", qErr);
            return db.rollback(() => {
              res.status(500).json({
                message: "삭제 실패",
                step: i,
                error: qErr.message || String(qErr),
                code: qErr.code || undefined,
              });
            });
          }

          // 마지막 단계에서 대상 게시물이 없으면 롤백
          if (i === steps.length - 1 && result && result.affectedRows === 0) {
            return db.rollback(() => {
              res.status(404).json({ message: "대상 게시물을 찾을 수 없습니다." });
            });
          }

          runStep(i + 1);
        });
      };

      runStep(0);
    });
  });
});

/**
 * --------------------------------------------------------------------
 * CATEGORY GROUPS
 * --------------------------------------------------------------------
 */
router.get("/category-groups", (req, res) => {
  const sql = `
    SELECT group_no, group_name, created_at
    FROM pin_category_groups
    ORDER BY group_no ASC
  `;
  db.query(sql, (err, rows) => {
    if (err) {
      console.error("[admin/category-groups] DB 오류:", err);
      return res.status(500).json({ message: "DB 오류(그룹 조회)" });
    }
    res.json(rows);
  });
});

/**
 * --------------------------------------------------------------------
 * CATEGORIES
 * --------------------------------------------------------------------
 */
router.get("/categories", (req, res) => {
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
      console.error("[admin/categories] 목록 조회 오류:", err);
      return res.status(500).json({ message: "DB 오류(목록 조회)" });
    }
    res.json(rows);
  });
});

router.post("/categories", (req, res) => {
  const group_no = Number(req.body.group_no);
  const category_name = (req.body.category_name || "").trim();

  if (!group_no || !category_name) {
    return res.status(400).json({ message: "group_no, category_name 필수" });
  }

  db.query(
    `SELECT 1 FROM pin_categories WHERE group_no = ? AND category_name = ? LIMIT 1`,
    [group_no, category_name],
    (dupErr, dupRows) => {
      if (dupErr) {
        console.error("[admin/categories] 중복 체크 오류:", dupErr);
        return res.status(500).json({ message: "DB 오류(중복 체크)" });
      }
      if (dupRows.length) {
        return res.status(409).json({ message: "이미 존재하는 문제 유형입니다." });
      }

      db.query(
        `INSERT INTO pin_categories (group_no, category_name, is_active, created_at)
         VALUES (?, ?, 1, NOW())`,
        [group_no, category_name],
        (insErr, result) => {
          if (insErr) {
            console.error("[admin/categories] 생성 오류:", insErr);
            return res.status(500).json({ message: "DB 오류(추가)" });
          }
          res.json({ success: true, category_no: result.insertId });
        }
      );
    }
  );
});

router.put("/categories/:categoryNo", (req, res) => {
  const categoryNo = Number(req.params.categoryNo);
  const group_no = Number(req.body.group_no);
  const category_name = (req.body.category_name || "").trim();

  if (!categoryNo || !group_no || !category_name) {
    return res.status(400).json({ message: "값이 올바르지 않습니다." });
  }

  db.query(`SELECT 1 FROM pin_categories WHERE category_no = ? LIMIT 1`, [categoryNo], (exErr, exRows) => {
    if (exErr) {
      console.error("[admin/categories] 존재 확인 오류:", exErr);
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
          console.error("[admin/categories] 중복 확인 오류:", dupErr);
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
              console.error("[admin/categories] 수정 오류:", upErr);
              return res.status(500).json({ message: "DB 오류(수정)" });
            }
            res.json({ success: true });
          }
        );
      }
    );
  });
});

router.patch("/categories/:categoryNo/status", (req, res) => {
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
        console.error("[admin/categories] 상태 변경 오류:", err);
        return res.status(500).json({ message: "DB 오류(상태 변경)" });
      }
      if (!result.affectedRows) {
        return res.status(404).json({ message: "존재하지 않는 문제 유형입니다." });
      }
      res.json({ success: true, is_active });
    }
  );
});

router.post("/categories/merge", (req, res) => {
  const from_category_no = Number(req.body.from_category_no);
  const to_category_no = Number(req.body.to_category_no);

  if (!from_category_no || !to_category_no || from_category_no === to_category_no) {
    return res.status(400).json({ message: "병합 값 오류" });
  }

  db.beginTransaction((txErr) => {
    if (txErr) {
      console.error("[admin/categories/merge] 트랜잭션 시작 오류:", txErr);
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
          console.error("[admin/categories/merge] 카테고리 조회 오류:", selErr);
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
              console.error("[admin/categories/merge] 매핑 이동 오류:", insErr);
              return db.rollback(() => res.status(500).json({ message: "병합 실패(이동)" }));
            }

            db.query(
              `DELETE FROM pin_post_categories WHERE category_no = ?`,
              [from_category_no],
              (delErr) => {
                if (delErr) {
                  console.error("[admin/categories/merge] from 매핑 삭제 오류:", delErr);
                  return db.rollback(() => res.status(500).json({ message: "병합 실패(정리)" }));
                }

                db.query(
                  `UPDATE pin_categories SET is_active = 0 WHERE category_no = ?`,
                  [from_category_no],
                  (upErr) => {
                    if (upErr) {
                      console.error("[admin/categories/merge] from 비활성 오류:", upErr);
                      return db.rollback(() =>
                        res.status(500).json({ message: "병합 실패(비활성)" })
                      );
                    }

                    db.commit((cErr) => {
                      if (cErr) {
                        console.error("[admin/categories/merge] commit 오류:", cErr);
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
