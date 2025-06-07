// gateway/middleware/auth.js
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../config");

module.exports = function (req, res, next) {
  const auth = req.header("Authorization")?.split(" ");
  if (auth?.[0] !== "Bearer" || !auth[1]) {
    return res.status(401).json({ error: "Missing bank JWT" });
  }
  try {
    req.bankBadge = jwt.verify(auth[1], JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: "Invalid badge" });
  }
};
