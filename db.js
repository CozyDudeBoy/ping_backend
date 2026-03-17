const mysql = require('mysql');

// DB 연결 풀 설정
const connection = mysql.createPool({
  connectionLimit: 10,
  host: 'mariadb',
  user: 'root',
  password: '1234',
  database: 'ping',
  multipleStatements: true,
  charset: 'utf8mb4'
});

// 연결 테스트
connection.getConnection((err, conn) => {
  if (err) {
    console.error('MYSQL 연결 실패 :', err);
    return;
  }
  console.log('MYSQL 연결 성공');
  conn.release();
});

module.exports = connection;
