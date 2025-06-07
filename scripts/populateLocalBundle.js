// bank-portal/bank-a/backend/scripts/populateLocalBundles.js

require("dotenv").config({
  path: require("path").resolve(__dirname, "../.env"),
}); // Load .env from backend folder
const mysql = require("mysql");
const fetch = require("node-fetch");
const crypto = require("crypto");
const util = require("util");

// --- Configuration ---
// Ensure these are correctly pointing to BANK B's DB
const dbConfig = {
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "bankb_portal", // Should be bankb_portal
};

// CUSTOMER_PORTAL_INTERNAL_API_URL from .env is usually http://localhost:3002/internal
// but the /account/rotate-key is not under /internal.
// So, we construct the base URL for the customer portal.
const CUSTOMER_PORTAL_BASE_URL = (
  process.env.CUSTOMER_PORTAL_INTERNAL_API_URL ||
  "http://localhost:3002/internal"
).replace("/internal", ""); // Produces http://localhost:3002

// --- Database Connection ---
const connection = mysql.createConnection(dbConfig);
const queryAsync = util.promisify(connection.query).bind(connection);

// --- AES Encryption Helper (Compatible with Customer Portal's aesEncrypt) ---
const AES_ALGORITHM = "aes-256-cbc";

function aesEncrypt(text, keyHex) {
  const key = Buffer.from(keyHex, "hex");
  if (key.length !== 32) {
    console.error("AES Key details:", {
      keyHexLength: keyHex.length,
      bufferLength: key.length,
    });
    throw new Error(
      `Invalid key length for AES-256. Must be 32 bytes (64 hex chars). Provided key (hex): ${keyHex.substring(
        0,
        10
      )}...`
    );
  }
  const iv = crypto.randomBytes(16); // Initialization Vector
  const cipher = crypto.createCipheriv(AES_ALGORITHM, key, iv);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted; // Prepend IV for decryption
}

// --- Main Script Logic ---
async function main() {
  try {
    console.log(`Connecting to BANK B's database: ${dbConfig.database}...`);
    await util.promisify(connection.connect).bind(connection)();
    console.log("Connected to BANK B's database.");

    const clientsToProcessSql = `
        SELECT 
            ukr.client_id, 
            ukr.customer_ktp, 
            ukr.customer_kyc
        FROM 
            user_kyc_request ukr
        LEFT JOIN 
            user_profiles up ON ukr.client_id = up.user_id
        WHERE 
            (up.user_id IS NULL OR up.encrypted_bundle IS NULL)
            AND ukr.customer_ktp IS NOT NULL 
            AND ukr.customer_kyc IS NOT NULL;
    `;
    // Add "LIMIT 1" to clientsToProcessSql for testing on a single client first

    console.log("Fetching clients needing local bundle population...");
    const clients = await queryAsync(clientsToProcessSql);

    if (clients.length === 0) {
      console.log(
        "No clients found needing local bundle population. All seem up-to-date."
      );
      return;
    }

    console.log(`Found ${clients.length} client(s) to process.`);

    for (const client of clients) {
      const userId = client.client_id;
      const rawKtpDataUri = client.customer_ktp;
      const rawKycDataUri = client.customer_kyc;

      console.log(`\nProcessing client_id: ${userId}...`);

      if (!rawKtpDataUri || !rawKycDataUri) {
        console.warn(
          `  Skipping client_id ${userId}: Missing KTP or KYC data in user_kyc_request.`
        );
        continue;
      }

      console.log(
        `  Calling Customer Portal to rotate/ensure key for user_id: ${userId}...`
      );
      // *** CORRECTED URL CONSTRUCTION ***
      const rotateKeyUrl = `${CUSTOMER_PORTAL_BASE_URL}/account/rotate-key`;
      console.log(`  Targeting Customer Portal endpoint: ${rotateKeyUrl}`);

      let cpResponseJson;
      try {
        const cpResponse = await fetch(rotateKeyUrl, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ userId: userId }),
        });

        const contentType = cpResponse.headers.get("content-type");
        if (!contentType || !contentType.includes("application/json")) {
          const textResponse = await cpResponse.text();
          console.error(
            `  Error: Customer Portal responded with non-JSON content for user_id ${userId}. Status: ${cpResponse.status}. URL: ${rotateKeyUrl}. Response: ${textResponse}`
          );
          console.warn(
            `  Skipping client_id ${userId} due to non-JSON response from Customer Portal.`
          );
          continue;
        }

        cpResponseJson = await cpResponse.json();

        if (
          !cpResponse.ok ||
          !cpResponseJson.success ||
          !cpResponseJson.newKey
        ) {
          console.error(
            `  Error response from Customer Portal for user_id ${userId}: ${cpResponse.status}`,
            cpResponseJson
          );
          console.warn(
            `  Skipping client_id ${userId} due to Customer Portal error.`
          );
          continue;
        }
        console.log(
          `  Successfully got newKey from Customer Portal for user_id ${userId}. Key starts with: ${cpResponseJson.newKey.substring(
            0,
            6
          )}...`
        );
      } catch (fetchError) {
        console.error(
          `  Network or parsing error calling Customer Portal (${rotateKeyUrl}) for user_id ${userId}:`,
          fetchError
        );
        console.warn(
          `  Skipping client_id ${userId} due to Customer Portal communication error.`
        );
        continue;
      }

      const newKeyFromCP = cpResponseJson.newKey;

      const bundleString = JSON.stringify({
        ktpData: rawKtpDataUri,
        kycData: rawKycDataUri,
      });

      console.log(
        `  Encrypting bundle for user_id ${userId} with the new key...`
      );
      let localEncryptedBundle;
      try {
        localEncryptedBundle = aesEncrypt(bundleString, newKeyFromCP);
      } catch (encryptionError) {
        console.error(
          `  Failed to encrypt bundle for user_id ${userId}:`,
          encryptionError
        );
        console.warn(`  Skipping client_id ${userId} due to encryption error.`);
        continue;
      }
      console.log(
        `  Bundle encrypted successfully for user_id ${userId}. Bundle starts with: ${localEncryptedBundle.substring(
          0,
          20
        )}...`
      );

      const upsertLocalBundleSql = `
        INSERT INTO user_profiles (user_id, encrypted_bundle, updated_at)
        VALUES (?, ?, NOW())
        ON DUPLICATE KEY UPDATE
            encrypted_bundle = VALUES(encrypted_bundle),
            updated_at = NOW();
      `;

      try {
        await queryAsync(upsertLocalBundleSql, [userId, localEncryptedBundle]);
        console.log(
          `  Successfully populated/updated local encrypted_bundle for user_id ${userId} in bankb_portal.user_profiles.`
        );
      } catch (dbUpsertError) {
        console.error(
          `  Database error updating local user_profiles for user_id ${userId}:`,
          dbUpsertError
        );
      }
    }

    console.log("\nScript finished processing clients.");
  } catch (error) {
    console.error("\nUnhandled error in main script:", error);
  } finally {
    if (connection) {
      console.log("Closing database connection.");
      connection.end();
    }
  }
}

main();
