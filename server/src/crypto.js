import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

// Loads (or creates on first run) the server's secrets:
//  - Ed25519 key pair used to sign commands and leases sent to laptops
//  - AES-256 master key used to encrypt escrowed BitLocker recovery keys
//    (PROTOTYPE stand-in for AWS KMS / Azure Key Vault)
//  - HMAC secret used to verify HR webhooks
export function loadSecrets(dataDir) {
  const file = path.join(dataDir, 'secrets.json');
  if (!fs.existsSync(file)) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    const fresh = {
      signingPrivateKey: privateKey.export({ type: 'pkcs8', format: 'pem' }),
      signingPublicKey: publicKey.export({ type: 'spki', format: 'pem' }),
      escrowMasterKey: crypto.randomBytes(32).toString('hex'),
      hrWebhookSecret: crypto.randomBytes(24).toString('hex'),
    };
    fs.writeFileSync(file, JSON.stringify(fresh, null, 2), { mode: 0o600 });
  }
  const s = JSON.parse(fs.readFileSync(file, 'utf8'));
  const publicKey = crypto.createPublicKey(s.signingPublicKey);
  // Raw 32-byte Ed25519 key = last 32 bytes of the SPKI DER encoding (what the Go agent pins).
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return {
    privateKey: crypto.createPrivateKey(s.signingPrivateKey),
    publicKeyB64: der.subarray(der.length - 32).toString('base64'),
    masterKey: Buffer.from(s.escrowMasterKey, 'hex'),
    hrWebhookSecret: process.env.HR_WEBHOOK_SECRET || s.hrWebhookSecret,
  };
}

// Signed envelope: { payload: base64(JSON bytes), sig: base64(Ed25519(JSON bytes)) }
export function signEnvelope(privateKey, obj) {
  const bytes = Buffer.from(JSON.stringify(obj), 'utf8');
  return {
    payload: bytes.toString('base64'),
    sig: crypto.sign(null, bytes, privateKey).toString('base64'),
  };
}

export function encrypt(masterKey, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', masterKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64');
}

export function decrypt(masterKey, blob) {
  const buf = Buffer.from(blob, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', masterKey, buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
}

export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${hash.toString('hex')}`;
}

export function verifyPassword(password, stored) {
  const [, saltHex, hashHex] = String(stored).split('$');
  if (!saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = crypto.scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return crypto.timingSafeEqual(expected, actual);
}

export function verifyHmac(secret, rawBody, signatureHex) {
  if (!signatureHex || !/^[0-9a-f]{64}$/i.test(signatureHex)) return false;
  const expected = crypto.createHmac('sha256', secret).update(rawBody).digest();
  return crypto.timingSafeEqual(expected, Buffer.from(signatureHex, 'hex'));
}
