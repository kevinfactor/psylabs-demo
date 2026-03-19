import crypto from 'crypto';

export default async function handler(req, res) {
  // CORS for the demo frontend
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { text } = req.body;
  if (!text) return res.status(400).json({ error: 'Missing text' });

  // Credentials from Vercel environment variables — never exposed to browser
  const apiKey          = process.env.X_API_KEY;
  const apiSecret       = process.env.X_API_SECRET;
  const accessToken     = process.env.X_ACCESS_TOKEN;
  const accessTokenSecret = process.env.X_ACCESS_TOKEN_SECRET;

  if (!apiKey || !apiSecret || !accessToken || !accessTokenSecret) {
    return res.status(500).json({
      error: 'Missing environment variables. Add X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET in Vercel settings.'
    });
  }

  const url    = 'https://api.x.com/2/tweets';
  const method = 'POST';

  // ── OAuth 1.0a signing ──────────────────────────────────────────────────
  const oauthParams = {
    oauth_consumer_key:     apiKey,
    oauth_nonce:            crypto.randomBytes(16).toString('hex'),
    oauth_signature_method: 'HMAC-SHA1',
    oauth_timestamp:        Math.floor(Date.now() / 1000).toString(),
    oauth_token:            accessToken,
    oauth_version:          '1.0',
  };

  // Signature base string — only OAuth params (not body for JSON requests)
  const paramStr = Object.keys(oauthParams)
    .sort()
    .map(k => `${encodeURIComponent(k)}=${encodeURIComponent(oauthParams[k])}`)
    .join('&');

  const baseStr  = `${method}&${encodeURIComponent(url)}&${encodeURIComponent(paramStr)}`;
  const sigKey   = `${encodeURIComponent(apiSecret)}&${encodeURIComponent(accessTokenSecret)}`;
  const signature = crypto.createHmac('sha1', sigKey).update(baseStr).digest('base64');

  oauthParams['oauth_signature'] = signature;

  const authHeader = 'OAuth ' + Object.keys(oauthParams)
    .sort()
    .map(k => `${encodeURIComponent(k)}="${encodeURIComponent(oauthParams[k])}"`)
    .join(', ');

  // ── Post the tweet ───────────────────────────────────────────────────────
  try {
    const response = await fetch(url, {
      method,
      headers: {
        'Authorization': authHeader,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    });

    const data = await response.json();

    if (response.ok && data.data?.id) {
      return res.status(200).json({
        success: true,
        id: data.data.id,
        url: `https://x.com/psylabseu/status/${data.data.id}`,
      });
    } else {
      console.error('X API error:', data);
      return res.status(response.status).json({
        success: false,
        error: data.detail || data.title || JSON.stringify(data),
      });
    }
  } catch (err) {
    console.error('Request failed:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
}
