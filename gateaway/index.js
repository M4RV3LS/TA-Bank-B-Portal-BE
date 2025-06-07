// bank-portal/bank-b/backend/gateaway/index.js
const express = require("express");
const ethers = require("ethers");
const jwt = require("jsonwebtoken");
const connection = require("../dbConnection"); // BANK B's DB Connection
const authMw = require("./middleware/auth");
const fetch = require("node-fetch");

const {
  PORT,
  JWT_SECRET,
  CHAIN_RPC,
  CONTRACT_ADDR,
  ENCRYPTED_BUNDLE_SQL,
  MY_BANK_ETHEREUM_ADDRESS,
  KNOWN_BANK_GATEWAYS,
} = require("./config");
const artifact = require("../abi/KycRegistryV3.json"); // Assuming this ABI is in bank-a/backend/abi

const app = express();
const provider = new ethers.JsonRpcProvider(CHAIN_RPC);
const contract = new ethers.Contract(CONTRACT_ADDR, artifact.abi, provider);

if (!MY_BANK_ETHEREUM_ADDRESS) {
  console.error(
    "[BANK B - Gateway FATAL] MY_BANK_ETHEREUM_ADDRESS is not configured. This is required."
  );
  process.exit(1);
}
if (!KNOWN_BANK_GATEWAYS || Object.keys(KNOWN_BANK_GATEWAYS).length === 0) {
  console.warn(
    "[BANK B - Gateway WARN] KNOWN_BANK_GATEWAYS is not configured or is empty. Fetching from Home Bank will likely fail."
  );
}

app.get("/kyc-files/:clientId", authMw, async (req, res) => {
  const clientId = Number(req.params.clientId);
  const originalRequesterAddress = req.bankBadge?.address?.toLowerCase();

  console.log(
    `[BANK B - Gateway /kyc-files] Request for clientId: ${clientId} from bank: ${originalRequesterAddress}`
  );

  if (!originalRequesterAddress) {
    console.error(
      "[BANK B - Gateway /kyc-files] Original requester address missing from auth badge."
    );
    return res
      .status(401)
      .json({ error: "Invalid authentication badge details." });
  }

  const myGatewayIdentityAddress = MY_BANK_ETHEREUM_ADDRESS.toLowerCase();
  let homeBankAddressOnChain = null; // Renamed to avoid confusion with KNOWN_BANK_GATEWAYS keys
  let isPermitted = false;

  try {
    console.log(
      `[BANK B - Gateway /kyc-files] On-chain check for clientId: ${clientId}, as gateway: ${myGatewayIdentityAddress}. Original requester: ${originalRequesterAddress}`
    );

    let versionCount = 0n; // Use BigInt for consistency with contract returns
    try {
      if (typeof contract.getVersionCount !== "function") {
        console.error(
          "[BANK B - Gateway /kyc-files] Smart contract 'getVersionCount' not found."
        );
        return res.status(500).json({
          error:
            "Internal server error: Contract misconfigured (getVersionCount).",
        });
      }
      versionCount = await contract.getVersionCount(clientId);
    } catch (e) {
      console.log(
        `[BANK B - Gateway /kyc-files] No KYC record for clientId ${clientId} (getVersionCount error):`,
        e.message
      );
    }

    if (versionCount > 0n) {
      if (typeof contract.getKycByVersion !== "function") {
        console.error(
          "[BANK B - Gateway /kyc-files] Smart contract 'getKycByVersion' not found."
        );
        return res.status(500).json({
          error:
            "Internal server error: Contract misconfigured (getKycByVersion).",
        });
      }
      const firstRecord = await contract.getKycByVersion(clientId, 1); // Version 1 determines home bank
      homeBankAddressOnChain = firstRecord?.issuer?.toLowerCase();

      if (homeBankAddressOnChain === myGatewayIdentityAddress) {
        isPermitted = true; // This gateway IS the Home Bank
        console.log(
          `[BANK B - Gateway /kyc-files] Access Check: This gateway (${myGatewayIdentityAddress}) IS Home Bank for clientId ${clientId}.`
        );
      } else {
        if (typeof contract.getParticipatingBanks !== "function") {
          console.error(
            "[BANK B - Gateway /kyc-files] Smart contract 'getParticipatingBanks' not found."
          );
          return res.status(500).json({
            error:
              "Internal server error: Contract misconfigured (getParticipatingBanks).",
          });
        }
        const participatingBanks = await contract.getParticipatingBanks(
          clientId
        );
        if (
          participatingBanks
            ?.map((addr) => addr.toLowerCase())
            .includes(originalRequesterAddress)
        ) {
          // The *requesting bank* (e.g. Bank B) must be a participant to get data via *this* gateway (BANK B)
          // AND this gateway (BANK B) must also be permitted if it's not the home bank but an intermediary (though current logic focuses on home bank or this gateway being participant for originalRequester)
          // For now, the main check is if this gateway itself is permitted to serve data FOR the original requester.
          // If BANK B is Home Bank, originalRequesterAddress doesn't strictly need to be a participant to ask BANK B for data it owns.
          // If BANK B is NOT Home Bank, but IS a participant, it might be fetching on behalf of originalRequesterAddress if originalRequesterAddress is also a participant.
          // The crucial permission is for THIS gateway to serve data TO the originalRequesterAddress.
          // The current logic checks if THIS gateway (myGatewayIdentityAddress) is a participant if it's not the Home Bank.
          // This is correct: if BANK B is a participant, it's allowed to access the data (potentially to serve to another participant).
          if (
            participatingBanks
              ?.map((addr) => addr.toLowerCase())
              .includes(myGatewayIdentityAddress)
          ) {
            isPermitted = true;
            console.log(
              `[BANK B - Gateway /kyc-files] Access Check: This gateway (${myGatewayIdentityAddress}) IS a Participating Bank for clientId ${clientId}. Home Bank is ${homeBankAddressOnChain}.`
            );
          }
        }
      }
    } else {
      console.log(
        `[BANK B - Gateway /kyc-files] Access Check: No KYC records found for clientId ${clientId}.`
      );
    }

    if (!isPermitted) {
      console.warn(
        `[BANK B - Gateway /kyc-files] Access DENIED for gateway ${myGatewayIdentityAddress} to serve clientId ${clientId} data to ${originalRequesterAddress}.`
      );
      return res.status(403).json({
        error:
          "Access Denied: This gateway is not authorized for the specified client's KYC data relative to the requester.",
      });
    }

    // --- If this gateway is permitted to act ---
    if (homeBankAddressOnChain === myGatewayIdentityAddress) {
      // This gateway IS THE HOME BANK: Serve from its own DB
      console.log(
        `[BANK B - Gateway /kyc-files] Is Home Bank. Fetching bundle for clientId: ${clientId} from own DB.`
      );
      connection.query(ENCRYPTED_BUNDLE_SQL, [clientId], (dbErr, rows) => {
        if (dbErr) {
          console.error(
            "[BANK B - Gateway /kyc-files] DB Error fetching bundle:",
            dbErr
          );
          if (!res.headersSent) {
            return res
              .status(500)
              .json({ error: "Database error while fetching KYC bundle." });
          }
          return;
        }
        if (!rows.length || !rows[0].encrypted_bundle) {
          console.warn(
            `[BANK B - Gateway /kyc-files] No bundle found in own DB for clientId: ${clientId}`
          );
          if (!res.headersSent) {
            return res.status(404).json({
              error: "KYC bundle not found for this client in Home Bank DB.",
            });
          }
          return;
        }
        const encryptedBundleHex = rows[0].encrypted_bundle;

        console.log(
          `[BANK B - Gateway /kyc-files] Serving bundle for clientId: ${clientId} from own DB.`
        );
        console.log(`  Bundle Length: ${encryptedBundleHex.length}`);
        console.log(
          `  Bundle Prefix (100): ${encryptedBundleHex.substring(0, 100)}...`
        );

        // Generate download token for the original requester
        const downloadToken = jwt.sign(
          { clientId, bank: originalRequesterAddress, bundleAccess: true },
          JWT_SECRET, // Use the shared JWT_SECRET from config
          { expiresIn: "5m" }
        );

        // Set headers BEFORE sending the response
        res.setHeader("X-Download-Token", downloadToken);
        res.setHeader("Content-Type", "application/text"); // Bundle is sent as plain text hex

        // Send response body ONCE
        res.send(encryptedBundleHex);
        console.log(
          `[BANK B - Gateway /kyc-files] Successfully served bundle from own DB for clientId: ${clientId}. Token issued to ${originalRequesterAddress}.`
        );
      });
    } else if (
      homeBankAddressOnChain &&
      KNOWN_BANK_GATEWAYS &&
      KNOWN_BANK_GATEWAYS[homeBankAddressOnChain]
    ) {
      // This gateway is a PARTICIPATING BANK, and it needs to fetch from the actual Home Bank's Gateway
      // This specific BANK B gateway will act as a client to the actual Home Bank's gateway.
      const actualHomeBankGatewayUrl =
        KNOWN_BANK_GATEWAYS[homeBankAddressOnChain];
      console.log(
        `[BANK B - Gateway /kyc-files] Is Participating Bank. Proxying request for clientId: ${clientId} from actual Home Bank ${homeBankAddressOnChain} at ${actualHomeBankGatewayUrl}.`
      );

      const interBankTokenPayload = {
        address: myGatewayIdentityAddress, // This gateway (BANK B) is the requester to the Home Bank Gateway
        purpose: `fetch_kyc_bundle_for_client_${clientId}_on_behalf_of_${originalRequesterAddress}`,
      };
      const interBankToken = jwt.sign(interBankTokenPayload, JWT_SECRET, {
        expiresIn: "5m",
      });

      try {
        const actualHomeBankResponse = await fetch(
          `${actualHomeBankGatewayUrl}/kyc-files/${clientId}`,
          {
            method: "GET",
            headers: { Authorization: `Bearer ${interBankToken}` },
          }
        );

        if (!actualHomeBankResponse.ok) {
          const errorBody = await actualHomeBankResponse.text();
          console.error(
            `[BANK B - Gateway /kyc-files] Error from Actual Home Bank Gateway (${actualHomeBankGatewayUrl}): ${actualHomeBankResponse.status} - ${errorBody}`
          );
          if (!res.headersSent) {
            return res
              .status(actualHomeBankResponse.status)
              .json({
                error: `Failed to retrieve KYC bundle from Home Bank. Status: ${actualHomeBankResponse.status}`,
                detail: errorBody,
              });
          }
          return;
        }

        const proxiedEncryptedBundleHex = await actualHomeBankResponse.text();
        const proxiedDownloadToken =
          actualHomeBankResponse.headers.get("x-download-token");

        console.log(
          `[BANK B - Gateway /kyc-files] Successfully fetched bundle from actual Home Bank for clientId: ${clientId}.`
        );

        // Forward the headers and body from the actual Home Bank response
        if (proxiedDownloadToken && !res.headersSent)
          res.setHeader("X-Download-Token", proxiedDownloadToken); // Or generate a new one for originalRequesterAddress
        if (!res.headersSent) res.setHeader("Content-Type", "application/text");
        if (!res.headersSent) res.send(proxiedEncryptedBundleHex);
      } catch (fetchError) {
        console.error(
          `[BANK B - Gateway /kyc-files] Network error fetching from Actual Home Bank Gateway (${actualHomeBankGatewayUrl}):`,
          fetchError
        );
        if (!res.headersSent) {
          return res.status(502).json({
            error:
              "Bad Gateway: Could not connect to Home Bank to retrieve KYC bundle.",
            detail: fetchError.message,
          });
        }
      }
    } else {
      console.error(
        `[BANK B - Gateway /kyc-files] Cannot serve bundle: Home Bank is ${homeBankAddressOnChain}, but its gateway URL is not in KNOWN_BANK_GATEWAYS or Home Bank not identified on-chain.`
      );
      if (!res.headersSent) {
        return res.status(500).json({
          error:
            "Internal Server Error: Home Bank gateway information missing or Home Bank could not be identified.",
        });
      }
    }
  } catch (onChainError) {
    console.error(
      `[BANK B - Gateway /kyc-files] Critical error during on-chain access check for clientId ${clientId}:`,
      onChainError
    );
    if (!res.headersSent) {
      return res.status(500).json({
        error: "Failed to process request due to blockchain interaction error.",
        detail: onChainError.message,
      });
    }
  }
});

app.listen(PORT, () => {
  console.log(`BANK B Gateway listening on http://localhost:${PORT}`);
  connection.getConnection((err, conn) => {
    if (err) {
      console.error(
        "❌ [BANK B - Gateway] MySQL Pool Error on startup:",
        err.message
      );
    } else {
      console.log(
        "✅ [BANK B - Gateway] Successfully connected to MySQL database pool."
      );
      conn.release();
    }
  });
});
