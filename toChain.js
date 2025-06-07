// bank-portal/bank-b/backend/toChain.js

require("dotenv").config();
const { ethers } = require("ethers");
const connection = require("./dbConnection"); // BANK B's DB connection
const util = require("util");

const KYCArtifact = require(__dirname + "/abi/KycRegistryV3.json");
const queryAsync = util.promisify(connection.query).bind(connection);

const {
  RPC_URL,
  PRIVATE_KEY,
  KYC_REGISTRY_ADDRESS,
  CUSTOMER_PORTAL_INTERNAL_API_URL,
} = process.env;

if (
  !PRIVATE_KEY ||
  !KYC_REGISTRY_ADDRESS ||
  !CUSTOMER_PORTAL_INTERNAL_API_URL ||
  !RPC_URL
) {
  console.error(
    "[BANK B - toChain.js config] ERROR: Missing one or more required .env variables (PRIVATE_KEY, KYC_REGISTRY_ADDRESS, CUSTOMER_PORTAL_INTERNAL_API_URL, RPC_URL)."
  );
  process.exit(1);
}

const provider = new ethers.JsonRpcProvider(RPC_URL);
const signer = new ethers.Wallet(PRIVATE_KEY, provider);
const kycContract = new ethers.Contract(
  KYC_REGISTRY_ADDRESS,
  KYCArtifact.abi,
  signer
);

function computeHash(input, label = "Input") {
  if (typeof input !== "string") {
    console.warn(
      `[BANK B - toChain - computeHash] ${label} is not a string for hashing, type: ${typeof input}. Hashing an empty string instead.`
    );
    return ethers.keccak256(ethers.toUtf8Bytes(""));
  }
  // console.log(`[BANK B - toChain - computeHash] Hashing ${label} (first 50 chars): ${input.substring(0,50)}... (length: ${input.length})`);
  return ethers.keccak256(ethers.toUtf8Bytes(input));
}

async function updateRequestStatus(requestId, newStatus, note = null) {
  try {
    const sql = note
      ? `UPDATE user_kyc_request SET status_kyc = ?, note = ? WHERE request_id = ?`
      : `UPDATE user_kyc_request SET status_kyc = ? WHERE request_id = ?`;
    const params = note ? [newStatus, note, requestId] : [newStatus, requestId];
    await queryAsync(sql, params);
    console.log(
      `[BANK B - toChain - updateRequestStatus] Request ${requestId} status updated to ${newStatus}` +
        (note ? ` with note: "${note}"` : "")
    );
  } catch (dbErr) {
    console.error(
      `[BANK B - toChain - updateRequestStatus] DB Error updating request ${requestId} to ${newStatus}:`,
      dbErr
    );
  }
}

async function callAddKycVersionOnContract(
  clientId,
  hashKtp,
  hashKyc,
  statusOnChain,
  ethAmountString
) {
  const txOverrides = {
    value: ethers.parseEther(ethAmountString),
  };
  console.log(
    `[BANK B - toChain - callAddKycVersion] For clientId ${clientId}: ETH: ${ethAmountString}, On-chain status: '${statusOnChain}', HashKTP: ${hashKtp}, HashKYC: ${hashKyc}`
  );

  const tx = await kycContract.addKycVersion(
    clientId,
    hashKtp,
    hashKyc,
    statusOnChain,
    txOverrides
  );
  console.log(
    `[BANK B - toChain - callAddKycVersion] Tx sent for clientId ${clientId}, hash: ${tx.hash}. Waiting...`
  );
  const receipt = await tx.wait();
  console.log(
    "---- FULL TRANSACTION RECEIPT ----\n",
    JSON.stringify(receipt, null, 2)
  );
  console.log(
    `[BANK B - toChain - callAddKycVersion] Tx mined for clientId ${clientId}, receipt status: ${
      receipt.status === 1 ? "Success" : "Failed"
    }`
  );

  if (receipt.status !== 1) {
    throw new Error(
      `On-chain transaction failed for addKycVersion. Tx hash: ${tx.hash}`
    );
  }

  let version = null;
  if (receipt.logs) {
    for (const log of receipt.logs) {
      try {
        const logDescription = kycContract.interface.parseLog({
          topics: [...log.topics],
          data: log.data,
        });
        if (logDescription && logDescription.name === "KycVersionAdded") {
          version = Number(logDescription.args.version);
          break;
        }
      } catch (_) {
        /* Ignore */
      }
    }
  }
  return { txHash: receipt.hash, version };
}

// NEW: Pass exact KTP/KYC data URIs to CP for bundle creation
async function syncBundleWithCustomerPortal(
  userId,
  ktpDataUriForBundle,
  kycDataUriForBundle,
  callingBankIdentifier
) {
  const customerPortalRotateKeyUrl = `${CUSTOMER_PORTAL_INTERNAL_API_URL.replace(
    "/internal",
    ""
  )}/account/rotate-key`;

  console.log(
    `[BANK B - toChain - syncBundleWithCP] Calling CP (${customerPortalRotateKeyUrl}) for user ${userId}.`
  );
  // console.log(`  Will send KTP data (len ${ktpDataUriForBundle?.length}, prefix 50): ${String(ktpDataUriForBundle).substring(0,50)}...`);
  // console.log(`  Will send KYC data (len ${kycDataUriForBundle?.length}, prefix 50): ${String(kycDataUriForBundle).substring(0,50)}...`);

  let cpResponseJson;
  try {
    const fetchModule = await import("node-fetch");
    const cpResponse = await fetchModule.default(customerPortalRotateKeyUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        userId: Number(userId),
        ktpData: ktpDataUriForBundle,
        kycData: kycDataUriForBundle,
        callingBankId: callingBankIdentifier, // e.g., "BANK_B" from process.env.THIS_BANK_IDENTIFIER
      }),
    });

    const responseText = await cpResponse.text();
    if (!cpResponse.ok) {
      console.error(
        `[BANK B - toChain - syncBundleWithCP] CP call failed for user ${userId}. Status: ${cpResponse.status}, Body: ${responseText}`
      );
      throw new Error(
        `Customer Portal key rotation failed: ${cpResponse.status} - ${responseText}`
      );
    }

    try {
      cpResponseJson = JSON.parse(responseText);
    } catch (parseError) {
      console.error(
        `[BANK B - toChain - syncBundleWithCP] Failed to parse JSON from CP for user ${userId}. Raw: ${responseText}`,
        parseError
      );
      throw new Error(
        "Customer Portal returned non-JSON response for key rotation."
      );
    }

    if (
      !cpResponseJson.success ||
      !cpResponseJson.newKey ||
      !cpResponseJson.newEncryptedBundle
    ) {
      console.error(
        `[BANK B - toChain - syncBundleWithCP] CP response missing required fields for user ${userId}. Response:`,
        cpResponseJson
      );
      throw new Error(
        "Customer Portal did not return all required data (newKey, newEncryptedBundle)."
      );
    }

    console.log(
      `[BANK B - toChain - syncBundleWithCP] Received from CP for user ${userId}:`
    );
    console.log(`  New Key (full): ${cpResponseJson.newKey}`);
    console.log(
      `  New Encrypted Bundle (length): ${cpResponseJson.newEncryptedBundle.length}`
    );
    console.log(
      `  New Encrypted Bundle (prefix 100): ${cpResponseJson.newEncryptedBundle.substring(
        0,
        100
      )}...`
    );

    const upsertLocalBundleSql = `
      INSERT INTO user_profiles (user_id, encrypted_bundle, updated_at)
      VALUES (?, ?, NOW())
      ON DUPLICATE KEY UPDATE
          encrypted_bundle = VALUES(encrypted_bundle),
          updated_at = NOW();
    `;
    await queryAsync(upsertLocalBundleSql, [
      userId,
      cpResponseJson.newEncryptedBundle,
    ]);
    console.log(
      `[BANK B - toChain - syncBundleWithCP] Successfully updated bankb_portal.user_profiles for user_id ${userId} with bundle from CP.`
    );

    return {
      newKey: cpResponseJson.newKey,
      newEncryptedBundle: cpResponseJson.newEncryptedBundle,
    };
  } catch (err) {
    console.error(
      `[BANK B - toChain - syncBundleWithCP] Error during sync for user ${userId}:`,
      err
    );
    throw err;
  }
}

async function sendToChain(requestRow) {
  const {
    request_id,
    client_id,
    customer_ktp,
    customer_kyc,
    status_request,
    status_kyc,
  } = requestRow;

  console.log(
    `[BANK B - sendToChain] Processing request_id: ${request_id}, client_id: ${client_id}, status_request: '${status_request}'`
  );

  const finalCustomerKtp = typeof customer_ktp === "string" ? customer_ktp : "";
  const finalCustomerKyc = typeof customer_kyc === "string" ? customer_kyc : "";

  // Log the exact data URIs that will be used for hashing AND sent to CP
  console.log(
    `[BANK B - sendToChain] Data for Hashing/Bundling - ClientID ${client_id}:`
  );
  console.log(
    `  finalCustomerKtp (len ${
      finalCustomerKtp.length
    }, prefix 70): ${finalCustomerKtp.substring(0, 70)}...`
  );
  console.log(
    `  finalCustomerKyc (len ${
      finalCustomerKyc.length
    }, prefix 70): ${finalCustomerKyc.substring(0, 70)}...`
  );

  const hashKtp = computeHash(finalCustomerKtp, `KTP for client ${client_id}`);
  const hashKyc = computeHash(finalCustomerKyc, `KYC for client ${client_id}`);
  console.log(
    `[BANK B - sendToChain] For client ${client_id}: HashKTP to be sent: ${hashKtp}, HashKYC to be sent: ${hashKyc}`
  );

  let onChainResult;

  try {
    let ethAmountString;
    let onChainVersionCount = 0;

    try {
      const countBigInt = await kycContract.getVersionCount(client_id);
      onChainVersionCount = Number(countBigInt);
    } catch (e) {
      console.warn(
        `[BANK B - sendToChain] kyc.getVersionCount for client ${client_id} failed or new client. Assuming 0. Error: ${e.message}`
      );
      onChainVersionCount = 0;
    }

    console.log(
      `[BANK B - sendToChain] Client ${client_id}: DB status_request '${status_request}', On-chain version count: ${onChainVersionCount}.`
    );

    if (status_request === "new") {
      if (onChainVersionCount > 0) {
        const errorMsg = `Client ${client_id} already on-chain (v: ${onChainVersionCount}), but request ${request_id} is 'new'.`;
        console.error(`[BANK B - sendToChain] ${errorMsg}`);
        await updateRequestStatus(
          request_id,
          "failed",
          "Data Inconsistency: Client already on-chain for 'new' request."
        );
        return { success: false, error: errorMsg };
      }
      ethAmountString = "1.0";
    } else if (status_request === "update") {
      if (onChainVersionCount === 0) {
        console.warn(
          `[BANK B - sendToChain] Client ${client_id} (request ${request_id}) is 'update' but not on-chain. Treating as initial submission (1.0 ETH).`
        );
        ethAmountString = "1.0";
      } else {
        ethAmountString = "0.1";
      }
    } else {
      const errorMsg = `Invalid status_request '${status_request}' for request ${request_id}.`;
      console.error(`[BANK B - sendToChain] ${errorMsg}`);
      await updateRequestStatus(
        request_id,
        "failed",
        `Invalid request type: ${status_request}`
      );
      return { success: false, error: errorMsg };
    }
    console.log(
      `[BANK B - sendToChain] Determined ETH amount for request ${request_id}: ${ethAmountString} ETH.`
    );

    onChainResult = await callAddKycVersionOnContract(
      client_id,
      hashKtp,
      hashKyc,
      status_kyc,
      ethAmountString
    );

    // Pass the exact data URIs used for hashing to the sync function
    await syncBundleWithCustomerPortal(
      client_id,
      finalCustomerKtp,
      finalCustomerKyc,
      process.env.THIS_BANK_IDENTIFIER
    );
    console.log(
      `[BANK B - sendToChain] Successfully executed CP bundle sync for client ${client_id} after on-chain update.`
    );

    await updateRequestStatus(request_id, "success");
    console.log(
      `[BANK B - sendToChain] Successfully processed KYC for request ${request_id} (client ${client_id}) on-chain and synced with CP. Tx: ${onChainResult.txHash}, Version: ${onChainResult.version}`
    );

    return {
      success: true,
      txHash: onChainResult.txHash,
      version: onChainResult.version,
    };
  } catch (err) {
    console.error(
      `[BANK B - sendToChain] Error processing request ${request_id} (client ${client_id}):`,
      err.message,
      err.stack
    );

    if (onChainResult && onChainResult.txHash) {
      console.error(
        `[BANK B - sendToChain] CRITICAL: On-chain TX for request ${request_id} (client ${client_id}) SUCCEEDED (Tx: ${onChainResult.txHash}), but bundle sync FAILED: ${err.message}.`
      );
      await updateRequestStatus(
        request_id,
        "success",
        `On-chain OK. CP Bundle Sync Failed: ${err.message.substring(0, 100)}`
      );
      return {
        success: true,
        txHash: onChainResult.txHash,
        version: onChainResult.version,
        warning:
          "On-chain TX successful, but Customer Portal bundle synchronization failed.",
        syncError: err.message,
      };
    } else {
      await updateRequestStatus(
        request_id,
        "failed",
        `Processing Error: ${err.message.substring(0, 150)}`
      );
      return { success: false, error: err.message };
    }
  }
}

module.exports = {
  sendToChain,
};

// Standalone Test (Optional)
if (require.main === module) {
  (async () => {
    // ... (Your existing standalone test mocks and logic) ...
  })();
}
