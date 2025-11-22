import express from "express";
import fetch from "node-fetch";

const app = express();

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_REDIRECT_URI,
  DISCORD_GUILD_ID,
  DISCORD_BOT_TOKEN,
  GITHUB_TOKEN,
  GITHUB_OWNER,
  GITHUB_REPO,
  WHITELIST_FILE,
  REQUIRED_ROLE_IDS,
  VERIFY_URL,
  PORT
} = process.env;

const requiredRoleIds = (REQUIRED_ROLE_IDS || "")
  .split(",")
  .map(x => x.trim())
  .filter(Boolean);

app.get("/", (req, res) => {
  res.send("duck-backend is running");
});

app.get("/auth/discord", (req, res) => {
  const redirect = new URL("https://discord.com/oauth2/authorize");
  redirect.searchParams.set("client_id", DISCORD_CLIENT_ID);
  redirect.searchParams.set("response_type", "code");
  redirect.searchParams.set("redirect_uri", DISCORD_REDIRECT_URI);
  redirect.searchParams.set("scope", "identify guilds guilds.members.read connections");
  redirect.searchParams.set("prompt", "consent");
  res.redirect(redirect.toString());
});

async function exchangeCodeForToken(code) {
  const body = new URLSearchParams();
  body.set("client_id", DISCORD_CLIENT_ID);
  body.set("client_secret", DISCORD_CLIENT_SECRET);
  body.set("grant_type", "authorization_code");
  body.set("code", code);
  body.set("redirect_uri", DISCORD_REDIRECT_URI);

  const resp = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });

  if (!resp.ok) throw new Error("Failed token exchange");
  return await resp.json();
}

async function fetchDiscordUser(tokenType, accessToken) {
  const resp = await fetch("https://discord.com/api/users/@me", {
    headers: { Authorization: `${tokenType} ${accessToken}` }
  });
  if (!resp.ok) throw new Error("Failed fetching user");
  return await resp.json();
}

async function fetchGuildMember(tokenType, accessToken) {
  const url = `https://discord.com/api/users/@me/guilds/${DISCORD_GUILD_ID}/member`;
  const resp = await fetch(url, {
    headers: { Authorization: `${tokenType} ${accessToken}` }
  });
  if (resp.status === 404 || resp.status === 403) return null;
  if (!resp.ok) throw new Error("Failed fetching guild member");
  return await resp.json();
}

async function getWhitelist() {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${WHITELIST_FILE}`;
  const resp = await fetch(url, {
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json"
    }
  });
  if (resp.status === 404) return { entries: [], sha: null };
  if (!resp.ok) throw new Error("Failed fetching whitelist");
  const json = await resp.json();
  const content = Buffer.from(json.content, "base64").toString("utf8");
  let entries;
  try {
    entries = JSON.parse(content);
  } catch {
    entries = [];
  }
  if (!Array.isArray(entries)) entries = [];
  return { entries, sha: json.sha };
}

async function saveWhitelist(entries, sha, actor) {
  const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${WHITELIST_FILE}`;
  const content = Buffer.from(JSON.stringify(entries, null, 2)).toString("base64");
  const body = {
    message: `Update whitelist for ${actor || "user"}`,
    content,
    sha: sha || undefined
  };
  const resp = await fetch(url, {
    method: "PUT",
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: "application/vnd.github+json"
    },
    body: JSON.stringify(body)
  });
  if (!resp.ok) {
    const txt = await resp.text();
    throw new Error("Failed saving whitelist: " + txt);
  }
}

app.get("/auth/discord/callback", async (req, res) => {
  const code = req.query.code;
  if (!code) {
    res.status(400).send("Missing code");
    return;
  }

  try {
    const tokenData = await exchangeCodeForToken(code);
    const { token_type, access_token } = tokenData;

    const user = await fetchDiscordUser(token_type, access_token);
    const member = await fetchGuildMember(token_type, access_token);

    if (!member) {
      res.status(403).send("You are not in the server.");
      return;
    }

    const roles = Array.isArray(member.roles) ? member.roles : [];
    const hasRequired =
      requiredRoleIds.length === 0 || roles.some(r => requiredRoleIds.includes(r));

    if (!hasRequired) {
      res.status(403).send("You do not have the required roles.");
      return;
    }

    const connectionsResp = await fetch("https://discord.com/api/users/@me/connections", {
      headers: { Authorization: `${token_type} ${access_token}` }
    });

    if (!connectionsResp.ok) throw new Error("Failed fetching connections");
    const connections = await connectionsResp.json();
    const roblox = connections.find(c => c.type === "roblox");

    if (!roblox) {
      res.status(400).send("No Roblox account connected to Discord.");
      return;
    }

    const robloxName = roblox.name || roblox.id || `roblox_${user.id}`;

    const { entries, sha } = await getWhitelist();
    if (!entries.find(e => e.roblox === robloxName)) {
      entries.push({
        discordId: user.id,
        roblox: robloxName,
        addedAt: new Date().toISOString()
      });
      await saveWhitelist(entries, sha, user.id);
    }

    const redirectUrl = VERIFY_URL || "https://example.com";
    res.send(
      `Success! Added ${robloxName} to whitelist. You can now run the script. You may close this page.`
    );
  } catch (err) {
    console.error(err);
    res.status(500).send("Internal error during Discord auth.");
  }
});

app.get("/check", async (req, res) => {
  const name = (req.query.name || "").trim();
  if (!name) {
    res.status(400).json({ allowed: false, reason: "missing_name" });
    return;
  }

  try {
    const { entries } = await getWhitelist();
    const isWhitelisted = entries.some(e => e.roblox === name);
    res.json({ allowed: isWhitelisted });
  } catch (err) {
    console.error(err);
    res.status(500).json({ allowed: false, reason: "server_error" });
  }
});

const port = Number(PORT) || 3000;
app.listen(port, () => {
  console.log("duck-backend listening on port", port);
});
