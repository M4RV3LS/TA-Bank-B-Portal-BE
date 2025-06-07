// File: E:\Coding\Tugas Akhir\bank-portal\bank-b\backend\gateaway\config.js

require("dotenv").config({
  // This path correctly points to the .env file in the bank-b/backend/ directory
  // when __dirname is E:\Coding\Tugas Akhir\bank-portal\bank-b\backend\gateaway
  path: require("path").resolve(__dirname, "../.env"),
});

// Optional: Add a log to confirm which .env file is being targeted
console.log(
  "[bank b Gateway Config] Loading .env from:",
  require("path").resolve(__dirname, "../.env")
);
console.log(
  "[bank b Gateway Config] MY_BANK_ETHEREUM_ADDRESS from env:",
  process.env.MY_BANK_ETHEREUM_ADDRESS
);

module.exports = {
  PORT: process.env.GATEWAY_PORT_BANK_B || 5100, // Use a specific env var for bank b's port or default
  JWT_SECRET: process.env.GATEWAY_JWT_SECRET_FOR_INTERBANK_AUTH, // Should be the same shared secret
  CHAIN_RPC: process.env.RPC_URL,
  CONTRACT_ADDR: process.env.KYC_REGISTRY_ADDRESS, // Assuming same contract

  // Database connection details for bank b's gateway (if it has its own user_profiles or other tables)
  // Adjust these if bank b's gateway uses a different DB or credentials
  DB_HOST: process.env.DB_HOST_BANK_B || process.env.DB_HOST || "localhost",
  DB_USER: process.env.DB_USER_BANK_B || process.env.DB_USER || "root",
  DB_PASSWORD: process.env.DB_PASSWORD_BANK_B || process.env.DB_PASSWORD || "",
  DB_NAME: process.env.GATEWAY_DB_NAME_BANK_B || "bankb_portal", // Specific to bank b

  // SQL query for bank b's gateway (if it ever acts as a Home Bank)
  ENCRYPTED_BUNDLE_SQL: `SELECT encrypted_bundle FROM user_profiles WHERE user_id = ?`,

  // Crucial for the "Fetch from Home Bank" logic
  MY_BANK_ETHEREUM_ADDRESS: process.env.MY_BANK_ETHEREUM_ADDRESS,
  KNOWN_BANK_GATEWAYS: {
    // Add known bank gateways here. Keys should be lowercase Ethereum addresses.
    // Example: If bank b's Ethereum address (its gateway identity) is '0xbankAaddress...'
    // and its gateway runs on port 4000 (for bank b's gateway, not bank b's main backend)
    "0x3c25db928b913d8d32569a76dc3a980e8c4b8670": "http://localhost:4100", // Replace with actual bank b address and its GATEWAY port
    // Add other bank gateways bank b might need to contact
  },
};
