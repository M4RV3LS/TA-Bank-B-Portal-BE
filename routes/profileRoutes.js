// path file : bank-portal/bank-b/backend/routes/profileRoutes.js
const express = require("express");
const router = express.Router();
const connection = require("../dbConnection");

/** GET /profile-ids
 *  Optional query: ?client_id=123
 *  Returns rows: { client_id, customer_name, profile_id }
 */
router.get("/", (req, res) => {
  const { client_id } = req.query;
  let sql = `
    SELECT 
      u.request_id,
      u.client_id,
      u.customer_name,
      p.profile_id
    FROM user_kyc_request AS u
    JOIN user_profile_id  AS p ON u.request_id = p.request_id
  `;
  const params = [];
  if (client_id) {
    sql += ` WHERE u.client_id = ?`;
    params.push(client_id);
  }
  connection.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});

module.exports = router;
