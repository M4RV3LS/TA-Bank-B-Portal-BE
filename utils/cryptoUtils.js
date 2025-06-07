// File: bank-portal/bank-b/backend/utils/cryptoUtils.js
const crypto = require("crypto");
const AES_ALGORITHM = "aes-256-cbc";

function aesEncrypt(text, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    throw new Error(
      "Invalid key length for AES-256. Must be 32 bytes (64 hex chars)."
    );
  }
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function aesDecrypt(encryptedTextWithIv, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    // AES-256 key is 32 bytes
    throw new Error(
      "Invalid key length for AES-256. Must be 32 bytes (64 hex chars)."
    );
  }
  const textParts = encryptedTextWithIv.split(":");
  if (textParts.length !== 2) {
    throw new Error("Invalid encrypted text format. Expected IV:Ciphertext.");
  }
  const iv = Buffer.from(textParts.shift(), "hex"); // IV is the first part
  const encryptedText = textParts.join(":"); // Ciphertext is the second
  if (iv.length !== 16) {
    // IV for AES-CBC is 16 bytes
    throw new Error("Invalid IV length. Must be 16 bytes for AES-CBC.");
  }
  const decipher = crypto.createDecipheriv(AES_ALGORITHM, key, iv); // AES_ALGORITHM is 'aes-256-cbc'
  let decrypted = decipher.update(encryptedText, "hex", "utf8");
  decrypted += decipher.final("utf8"); // LINE 25 is likely this one
  return decrypted;
}
module.exports = { aesEncrypt, aesDecrypt };
