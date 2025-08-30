const fs = require('fs');
const sss = require('shamir-secret-sharing');

// Convert string in any base to hex string safely using BigInt
function baseStringToHex(str, base) {
  const digits = '0123456789abcdefghijklmnopqrstuvwxyz';
  base = BigInt(base);
  str = str.toLowerCase();

  let result = 0n;
  for (const ch of str) {
    const val = BigInt(digits.indexOf(ch));
    if (val === -1n) throw new Error('Invalid character for base conversion');
    result = result * base + val;
  }
  let hex = result.toString(16);
  if (hex.length % 2 !== 0) hex = '0' + hex;
  return hex;
}

// Convert hex string to Uint8Array
function hexStringToUint8Array(hex) {
  if (hex.length % 2 !== 0) hex = '0' + hex;
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) {
    arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return arr;
}

// Pad bytes to fixed length (right aligned)
function padDataBytes(data, length) {
  if (data.length >= length) return data;
  const padded = new Uint8Array(length);
  padded.set(data, length - data.length);
  return padded;
}

// Format shares, ensuring unique index and equal length
function formatSharesFromJSON(json) {
  const data = typeof json === 'string' ? JSON.parse(json) : json;
  const sharesData = [];
  let maxDataLen = 0;

  for (const key in data) {
    if (key !== 'keys') {
      const base = data[key].base;
      const val = data[key].value;
      const hexVal = baseStringToHex(val, base);
      sharesData.push({ index: parseInt(key), hexVal });
      maxDataLen = Math.max(maxDataLen, hexVal.length / 2);
    }
  }

  const shares = sharesData.map(({ index, hexVal }) => {
    let dataBytes = hexStringToUint8Array(hexVal);
    dataBytes = padDataBytes(dataBytes, maxDataLen);
    const share = new Uint8Array(1 + maxDataLen);
    share[0] = index;
    share.set(dataBytes, 1);
    return share;
  });

  // Check for duplicates
  const seen = new Set();
  for (const share of shares) {
    const hex = Buffer.from(share).toString('hex');
    if (seen.has(hex)) {
      throw new Error(`Duplicate share detected for hex: ${hex}`);
    }
    seen.add(hex);
  }

  return shares;
}

// Convert shares to points (index, numeric value) for polynomial checks
function sharesToPoints(shares) {
  return shares.map(s => {
    const x = BigInt(s[0]);
    let y = 0n;
    for (let i = 1; i < s.length; i++) {
      y = (y << 8n) + BigInt(s[i]);
    }
    return [x, y];
  });
}

// Compute multiplicative inverse modulo a large prime (simplified)
function modInverse(a, p) {
  // Extended Euclidean algorithm
  let m0 = p, t, q;
  let x0 = 0n, x1 = 1n;
  let aa = a;
  if (p === 1n) return 0n;
  while (aa > 1n) {
    q = aa / p;
    t = p;
    p = aa % p;
    aa = t;
    t = x0;
    x0 = x1 - q * x0;
    x1 = t;
  }
  if (x1 < 0n) x1 += m0;
  return x1;
}

// Lagrange interpolation at zero modulo a prime
function lagrangeInterpolationAtZero(points, prime) {
  let secret = 0n;
  const k = points.length;
  for (let i = 0; i < k; i++) {
    let [xi, yi] = points[i];
    let li = 1n;
    for (let j = 0; j < k; j++) {
      if (j !== i) {
        let xj = points[j][0];
        li = (li * (0n - xj) * modInverse(xi - xj, prime)) % prime;
      }
    }
    secret = (prime + secret + (yi * li)) % prime;
  }
  return secret;
}

// Detect wrong shares comparing against polynomial reconstructed from threshold shares
function detectWrongShares(shares, threshold, prime) {
  if (shares.length < threshold) return { secret: null, wrongShares: [] };
  const points = sharesToPoints(shares);
  const subset = points.slice(0, threshold);

  const secret = lagrangeInterpolationAtZero(subset, prime);

  const wrongShares = [];
  for (const [x, y] of points) {
    let yEstimate = 0n;
    for (let i = 0; i < subset.length; i++) {
      let [xi, yi] = subset[i];
      let li = 1n;
      for (let j = 0; j < subset.length; j++) {
        if (j !== i) {
          let xj = subset[j][0];
          li = (li * (x - xj) * modInverse(xi - xj, prime)) % prime;
        }
      }
      yEstimate = (yEstimate + yi * li) % prime;
    }
    if (yEstimate !== y) {
      wrongShares.push([Number(x), y.toString()]);
    }
  }
  return { secret, wrongShares };
}

// A large prime number for modulo operations (must be > max secret and shares numeric values)
const PRIME = 2n ** 521n - 1n; // example large prime (Mersenne prime)

async function processFile(filename) {
  try {
    const rawData = await fs.promises.readFile(filename, 'utf-8');
    const jsonData = JSON.parse(rawData);

    const shares = formatSharesFromJSON(jsonData);
    const threshold = jsonData.keys.k;

    const secretBytes = await sss.combine(shares);
    const secretBuffer = Buffer.from(secretBytes);

    const { secret, wrongShares } = detectWrongShares(shares, threshold, PRIME);

    console.log(`Reconstructed Secret from ${filename}:`);
    console.log('UTF-8:', secretBuffer.toString('utf8'));
    console.log('Hex:', secretBuffer.toString('hex'));
    console.log('Base64:', secretBuffer.toString('base64'));

    if (wrongShares.length > 0) {
      console.log('Wrong shares detected (index, value):');
      wrongShares.forEach(([index, val]) => {
        console.log(`Index: ${index}, Value: ${val}`);
      });
    } else {
      console.log('No wrong shares detected.');
    }
    console.log('----------------------------------');

  } catch (err) {
    console.error(`Error processing file ${filename}:`, err.message);
  }
}

(async () => {
  await processFile('shares.json');
  await processFile('shares2.json');
})();
