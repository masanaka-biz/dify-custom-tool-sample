import 'dotenv/config';
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuid } from 'uuid';

const app = express();
app.use(express.json());

const {
  PORT = 3000,
  JWT_PRIVATE_KEY = 'dev-key',
  TOKEN_TTL_SEC = 3600
} = process.env;

// -------------------- 簡易ユーザーDB（実運用はRDB/ID基盤） --------------------
/** 例: 事前登録ユーザー */
const users = new Map(); // key: username, val: { username, passhash }
users.set('alice', { username: 'alice', passhash: bcrypt.hashSync('alicepass', 10) });
users.set('bob',   { username: 'bob',   passhash: bcrypt.hashSync('bobpass', 10) });

// -------------------- トークン＆ペンディング認可 --------------------
/** user_idごとのアクセストークンをMCP側が保持（Difyへは渡さない運用でもOK） */
const tokenStore = new Map(); // key: user_id, val: { access_token, exp }

/** デバイス風のPending認可: user_code -> { user_id, expires_at, verified } */
const pendingAuth = new Map();

// -------------------- 補助 --------------------
function issueAccessToken(user_id) {
  const exp = Math.floor(Date.now()/1000) + Number(TOKEN_TTL_SEC);
  const token = jwt.sign({ sub: user_id, scope: 'basic' }, JWT_PRIVATE_KEY, { algorithm: 'HS256', expiresIn: Number(TOKEN_TTL_SEC) });
  tokenStore.set(user_id, { access_token: token, exp });
  return token;
}
function hasValidToken(user_id) {
  const rec = tokenStore.get(user_id);
  if (!rec) return false;
  return rec.exp - Math.floor(Date.now()/1000) > 30;
}

// -------------------- 1) 認可開始（Dify→MCP） --------------------
app.post('/local-auth/start', (req, res) => {
  const { user_id } = req.body || {};
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });

  // 有効トークンがあれば即OK
  if (hasValidToken(user_id)) {
    return res.json({ already_authorized: true });
  }

  // ユーザーコードを発行（簡易実装では8文字）
  const user_code = uuid().slice(0, 8).replace(/-/g, '').toUpperCase();
  const expires_at = Date.now() + 10 * 60 * 1000; // 10分
  pendingAuth.set(user_code, { user_id, expires_at, verified: false });

  // ユーザーが開くURL（MCPホストの認可ページ）
  const verification_uri = `http://localhost:${PORT}/local-auth/activate`;

  return res.json({
    requires_auth: true,
    verification_uri,
    user_code,
    expires_in: 600,
    message: 'ブラウザで verification_uri を開き、user_code と資格情報で認可してください。'
  });
});

// -------------------- 2) 認可ページ（ユーザーが開くUI） --------------------
// 超簡易版: フォームHTMLを返す（実運用はテンプレ/フロントアプリ）
app.get('/local-auth/activate', (req, res) => {
  res.type('html').send(`
    <html><body>
      <h2>MCP ローカル認可</h2>
      <form method="POST" action="/local-auth/activate">
        <label>User Code: <input name="user_code" /></label><br/>
        <label>Username: <input name="username" /></label><br/>
        <label>Password: <input type="password" name="password" /></label><br/>
        <button type="submit">Authorize</button>
      </form>
    </body></html>
  `);
});
app.use(express.urlencoded({ extended: true }));
app.post('/local-auth/activate', (req, res) => {
  const { user_code, username, password } = req.body || {};
  if (!user_code || !username || !password) return res.status(400).send('missing fields');

  const pending = pendingAuth.get(user_code);
  if (!pending) return res.status(400).send('invalid user_code');
  if (pending.expires_at < Date.now()) {
    pendingAuth.delete(user_code);
    return res.status(400).send('user_code expired');
  }

  const user = users.get(username);
  if (!user || !bcrypt.compareSync(password, user.passhash)) {
    return res.status(401).send('invalid credentials');
  }

  // 認証OK → user_codeを検証済みに
  pending.verified = true;
  pendingAuth.set(user_code, pending);

  // 即時トークン発行しても良いし、ポーリングで発行でも良い
  // ここでは即時発行＆保存（user_idに紐付け）
  issueAccessToken(pending.user_id);

  return res.status(200).send('Authorization success. このウィンドウを閉じてアプリに戻ってください。');
});

// -------------------- 3) Difyからのツール呼び出し --------------------
app.post('/tool/dice', (req, res) => {
  const { user_id, payload } = req.body || {};
  if (!user_id) return res.status(400).json({ error: 'user_id is required' });

  // トークンがなければ認可開始案内
  if (!hasValidToken(user_id)) {
    // 認可開始フローを内包して返す（UI側はそのまま表示してユーザーに案内）
    const user_code = uuid().slice(0, 8).replace(/-/g, '').toUpperCase();
    const expires_at = Date.now() + 10 * 60 * 1000;
    pendingAuth.set(user_code, { user_id, expires_at, verified: false });

    const verification_uri = `http://localhost:${PORT}/local-auth/activate`;
    return res.status(401).json({
      requires_auth: true,
      verification_uri,
      user_code,
      expires_in: 600,
      message: 'ブラウザで verification_uri を開き、user_code と資格情報で認可してください。'
    });
  }

  // ここからが本来の処理（外部API代理でも、MCP内のリソース提供でもOK）
  const token = tokenStore.get(user_id).access_token;
  // 例としてダミー応答
  return res.json({
    ok: true,
    data: { echo: payload ?? null, token_claims: jwt.decode(token) }
  });
});

app.listen(PORT, () => {
  console.log(`MCP local-IdP server listening on :${PORT}`);
});

