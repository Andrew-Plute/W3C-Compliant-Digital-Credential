const crypto = require('crypto');

function createVerificationMethodId(publicKeyBase64, did) {
  const hash = crypto.createHash('sha256').update(publicKeyBase64).digest('hex');
  return `${did}#${hash.substring(0, 16)}`;
}

function canonicalize(obj) {
  if (typeof obj !== 'object' || obj === null) {
    return obj;
  }
  if (Array.isArray(obj)) {
    return obj.map(canonicalize);
  }
  return Object.keys(obj).sort().reduce((acc, key) => {
    acc[key] = canonicalize(obj[key]);
    return acc;
  }, {});
}

function createEd25519KeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64')
  };
}

function createProof(data, privateKeyDer) {
  const canonical = JSON.stringify(canonicalize(data));
  const dataToSign = Buffer.from(canonical);
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyDer, 'base64'),
    format: 'der',
    type: 'pkcs8'
  });
  return crypto.sign(null, dataToSign, privateKey).toString('base64');
}

function verifyProof(doc, publicKeyDer) {
  if (!doc.proof || !doc.proof.proofValue) {
    throw new Error("Document is missing a proof or proofValue.");
  }
  const { proofValue, ...proofMetadata } = doc.proof;
  const signature = Buffer.from(proofValue, 'base64');
  const { proof, ...body } = doc;
  const dataThatWasSigned = { ...body, proof: proofMetadata };
  const canonical = JSON.stringify(canonicalize(dataThatWasSigned));
  const dataToVerify = Buffer.from(canonical);
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyDer, 'base64'),
    format: 'der',
    type: 'spki'
  });
  return crypto.verify(null, dataToVerify, publicKey, signature);
}

module.exports = {
  canonicalize,
  createEd25519KeyPair,
  createProof,
  verifyProof,
  createVerificationMethodId,
  crypto
};