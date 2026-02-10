const express = require('express');
const jwt = require('jsonwebtoken');
const db=require('../db');

const router = express.Router();
const JWT_SECRET = 'ping_secret_key';

/*
질문 등록
POST /qna/questions
 */
router.post('/questions', (req, res) => {
    const authHeader = req.headers.authorization;

    if(!authHeader) {
        return res.status(401).json({ message: '토근 없음'});
    }

    const token = authHeader.split(' ')[1];
    if(!token){
        return res.status(401).json({ message: '토근 형식 오류'});
    }

    let decoded;
    try{
        decoded = jwt.verify(token, JWT_SECRET);
    }catch (err) {
        return res.status(401).json({ message: '토근 검증 실패'});
    }

    const {user_no} = decoded;
    const{title, content} = req.body;

    if(!title || !content) {
        return res.status(400).json({message:'제목과 내용을 입력하세요'});
    }

    const sql = `
    INSERT INTO pin_qna_questions
    (user_no, question_title, question_content)
    VALUES (?, ?, ?)
    `;

    db.query(sql, [user_no, title, content], (err, result) => {
        if(err){
            console.error(err);
            return res.status(500).json({message: '질문 등록 실패'});
        }
        res.status(201).json({
            message:'질문 등록 완료',
            question_no: result.insertId,
        });
    });
});

/*
질문 목록 조회 
GET /qusetions
*/
router.get('/questions', (req,res)=>{
    const sql = `
    SELECT 
    q.question_no As no,
    q.question_title As title,
    u.user_nickname As author,
    q.create_datetime As date,
    a.answer_content As answer
    FROM pin_qna_questions q
    JOIN pin_users u ON q.user_no = u.user_no
    LEFT JOIN pin_qna_answers a ON q.question_no = a.question_no
    ORDER BY q.create_datetime DESC
    `;

    db.query(sql, (err, rows) => {
        if(err){
            console.error(err);
            return res.status(500).json({ message: '질문 조회 실패'});
        }

        res.json(rows);
    });
});

module.exports = router;
