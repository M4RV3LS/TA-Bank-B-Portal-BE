// gateway/generateBadge.js
const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, "../.env") }); // Explicit path

const jwt = require("jsonwebtoken");

// Use the correct environment variable for Bank B's Ethereum address
const bankBEthereumAddress = process.env.MY_BANK_ETHEREUM_ADDRESS;

if (!bankBEthereumAddress) {
  console.error("Error: MY_BANK_ETHEREUM_ADDRESS is not set in the .env file.");
  process.exit(1);
}
if (!process.env.GATEWAY_JWT_SECRET_FOR_INTERBANK_AUTH) {
  console.error(
    "Error: GATEWAY_JWT_SECRET_FOR_INTERBANK_AUTH is not set in the .env file."
  );
  process.exit(1);
}

const badge = jwt.sign(
  { address: bankBEthereumAddress }, // Use the correct address
  process.env.GATEWAY_JWT_SECRET_FOR_INTERBANK_AUTH,
  { expiresIn: "365d" } // Consider a shorter expiry if appropriate for its use
);

console.log("Generated Bank B Gateway Badge:", badge);
