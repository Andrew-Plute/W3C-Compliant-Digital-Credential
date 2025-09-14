const http = require('http');
const { verifyProof } = require('./shared');

const PORT = 3003;
const ISSUER_API_BASE = 'http://localhost:3001';
const HOLDER_API_BASE = 'http://localhost:3002';

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      if (res.statusCode < 200 || res.statusCode >= 300) {
        return reject(new Error(`Request to ${url} failed with status ${res.statusCode}`));
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch (e) {
          reject(new Error(`Failed to parse JSON from ${url}: ${e.message}`));
        }
      });
    }).on('error', reject);
  });
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/verify') {
    console.log('\n================================================');
    console.log('[Verifier] Received request. Starting verification flow...');
    console.log('================================================');
    try {
      console.log(`[Verifier] 1. Requesting a **Verifiable Presentation** from Holder at ${HOLDER_API_BASE}/present`);
      const presentation = await httpGet(`${HOLDER_API_BASE}/present`);
      console.log('[Verifier]    ...Signed Presentation received. This is the "envelope" signed by the Holder.');

      console.log('\n[Verifier] 2. Verifying the Presentation signature to confirm the Holder\'s identity...');
      const holderKeyData = await httpGet(`${HOLDER_API_BASE}/public-key`);
      if (!verifyProof(presentation, holderKeyData.publicKeyBase64)) {
        throw new Error("Holder's presentation signature is INVALID.");
      }
      console.log(`[Verifier]    - SUCCESS: Presentation signature is VALID. We trust the presenter is ${presentation.holder}.`);

      console.log('\n[Verifier] 3. Extracting the Verifiable Credentials from inside the Presentation...');
      const vcs = presentation.verifiableCredential;
      if (!vcs || vcs.length === 0) throw new Error("No credentials found in the presentation.");
      console.log(`[Verifier]    - Found ${vcs.length} credentials to verify.`);
      
      console.log('\n[Verifier] 4. Verifying each Credential\'s signature to confirm its authenticity...');
      const issuerKeyData = await httpGet(`${ISSUER_API_BASE}/public-key`); // Get key once
      
      // --- THIS IS THE MAJOR CHANGE ---
      let overallResult = 'VALID';
      const verificationResults = [];

      for (const [index, vc] of vcs.entries()) {
        const vcNumber = index + 1;
        console.log(`\n[Verifier] --> Verifying Credential #${vcNumber} (type: "${vc.type[1]}") from issuer "${vc.issuer}"...`);
        
        const isVcValid = verifyProof(vc, issuerKeyData.publicKeyBase64);
        
        if (isVcValid) {
          console.log(`[Verifier]    - SUCCESS: Credential #${vcNumber} signature is VALID.`);
        } else {
          console.log(`[Verifier]    - FAILURE: Credential #${vcNumber} signature is INVALID. The data was likely tampered with!`);
          overallResult = 'CONTAINS_INVALID'; // Downgrade the overall result
        }
        verificationResults.push({ 
          credentialType: vc.type[1],
          credentialSubject: vc.credentialSubject,
          isValid: isVcValid 
        });
      }
      // --------------------------

      console.log('\n-------------------------------------------------');
      console.log(`[Verifier] OVERALL RESULT: ${overallResult}`);
      if (overallResult === 'VALID') {
        console.log('The Holder is authentic, and ALL Credentials they presented are also authentic.');
      } else {
        console.log('The Holder is authentic, but ONE OR MORE Credentials they presented were INVALID/TAMPERED.');
      }
      console.log('-------------------------------------------------');
      res.writeHead(200, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ overallResult, verificationDetails: verificationResults }, null, 2));

    } catch (e) {
      console.error(`\n--- !!! VERIFICATION FAILED !!! ---`);
      console.error(`[Verifier] Reason: ${e.message}`);
      res.writeHead(500, {'Content-Type': 'application/json'});
      res.end(JSON.stringify({ error: 'Verification failed.', details: e.message }));
    }
  } else {
    res.writeHead(404).end('Not Found');
  }
});

server.listen(PORT, () => {
  console.log('--- Verifier Service Started ---');
  console.log(`Listening on http://localhost:${PORT}`);
  console.log(`--> To test, run: curl http://localhost:3003/verify`);
});