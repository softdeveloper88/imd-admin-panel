const initSqlJs = require('sql.js');
const fs = require('fs');
const crypto = require('crypto');
const zlib = require('zlib');

const PASSWORD = 'hs;d,hghdk[;ak';
const IV = Buffer.from([17,115,105,102,103,104,111,107,108,122,120,119,118,98,110,109]);

function deriveKey(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 19, 16, 'sha1');
}

function decryptText(enc, saltStr) {
  const s = saltStr.padEnd(8, '\0').slice(0, 8);
  const key = deriveKey(PASSWORD, s);
  const decipher = crypto.createDecipheriv('aes-128-cbc', key, IV);
  decipher.setAutoPadding(true);
  const dec = Buffer.concat([decipher.update(Buffer.from(enc, 'base64')), decipher.final()]);
  return zlib.gunzipSync(dec).toString('utf8');
}

(async () => {
  const SQL = await initSqlJs();
  const buf = fs.readFileSync('content/springer-978-981-10-5305-4-epub/springer-978-981-10-5305-4.db');
  const db = new SQL.Database(buf);
  const row = db.exec('SELECT id, doc FROM Docs WHERE id=3');
  const id = row[0].values[0][0];
  const doc = row[0].values[0][1];
  try {
    const decrypted = decryptText(doc, String(id));
    console.log(decrypted.substring(0, 500));
  } catch(e) {
    console.log('Error:', e.message);
  }
})();
