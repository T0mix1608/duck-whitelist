import express from "express"
import fetch from "node-fetch"
import dotenv from "dotenv"
dotenv.config()

const app = express()

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
} = process.env

const requiredRoles = (REQUIRED_ROLE_IDS || "").split(",").map(s => s.trim()).filter(Boolean)

app.get("/auth/discord", (req, res) => {
    const params = new URLSearchParams({
        client_id: DISCORD_CLIENT_ID,
        redirect_uri: DISCORD_REDIRECT_URI,
        response_type: "code",
        scope: "identify connections"
    })
    res.redirect(`https://discord.com/api/oauth2/authorize?${params.toString()}`)
})

app.get("/auth/discord/callback", async (req, res) => {
    const code = req.query.code
    if (!code) return res.status(400).send("No code")
    const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
        method: "POST",
        body: new URLSearchParams({
            client_id: DISCORD_CLIENT_ID,
            client_secret: DISCORD_CLIENT_SECRET,
            grant_type: "authorization_code",
            code,
            redirect_uri: DISCORD_REDIRECT_URI
        }),
        headers: { "Content-Type": "application/x-www-form-urlencoded" }
    })
    const tokenData = await tokenRes.json()
    if (!tokenData.access_token) return res.status(500).send("Failed to get access token")
    const accessToken = tokenData.access_token
    const userRes = await fetch("https://discord.com/api/users/@me", {
        headers: { Authorization: `Bearer ${accessToken}` }
    })
    const user = await userRes.json()
    const memberRes = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${user.id}`,
        { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    )
    if (!memberRes.ok) return res.status(403).send("You are not in the server")
    const member = await memberRes.json()
    const memberRoles = Array.isArray(member.roles) ? member.roles : []
    const hasRequiredRole = memberRoles.some(r => requiredRoles.includes(r))
    if (!hasRequiredRole) return res.status(403).send("You do not have the required role")
    const connRes = await fetch("https://discord.com/api/users/@me/connections", {
        headers: { Authorization: `Bearer ${accessToken}` }
    })
    const connections = await connRes.json()
    const robloxConn = Array.isArray(connections) ? connections.find(c => c.type === "roblox") : null
    if (!robloxConn) return res.status(400).send("You must connect your Roblox account in Discord settings")
    const robloxName = robloxConn.name
    try {
        await upsertWhitelistEntry(robloxName, user.id)
        return res.send(`Success! Added ${robloxName} to whitelist.`)
    } catch (e) {
        return res.status(500).send("Failed to update whitelist")
    }
})

async function getWhitelistFile() {
    const res = await fetch(
        `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${WHITELIST_FILE}`,
        { headers: { Authorization: `Bearer ${GITHUB_TOKEN}` } }
    )
    if (!res.ok) throw new Error("Failed to fetch whitelist file")
    const json = await res.json()
    const sha = json.sha
    const content = Buffer.from(json.content, "base64").toString("utf8")
    let list = []
    try {
        const parsed = JSON.parse(content)
        if (Array.isArray(parsed)) list = parsed
    } catch { }
    return { list, sha }
}

async function upsertWhitelistEntry(robloxName, discordId) {
    const { list, sha } = await getWhitelistFile()
    const existing = list.find(e => e.robloxName === robloxName || e.discordId === discordId)
    if (existing) {
        existing.robloxName = robloxName
        existing.discordId = discordId
    } else {
        list.push({ robloxName, discordId })
    }
    const newContent = Buffer.from(JSON.stringify(list, null, 2)).toString("base64")
    await fetch(
        `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${WHITELIST_FILE}`,
        {
            method: "PUT",
            headers: {
                Authorization: `Bearer ${GITHUB_TOKEN}`,
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                message: `Update whitelist for ${robloxName}`,
                content: newContent,
                sha
            })
        }
    )
}

async function getMemberById(discordId) {
    const res = await fetch(
        `https://discord.com/api/guilds/${DISCORD_GUILD_ID}/members/${discordId}`,
        { headers: { Authorization: `Bot ${DISCORD_BOT_TOKEN}` } }
    )
    if (!res.ok) return null
    return res.json()
}

app.get("/check", async (req, res) => {
    const robloxName = req.query.name
    if (!robloxName) return res.status(400).json({ allowed: false, verifyUrl: VERIFY_URL || null })
    try {
        const { list } = await getWhitelistFile()
        const entry = list.find(e => e.robloxName === robloxName)
        if (!entry) return res.json({ allowed: false, verifyUrl: VERIFY_URL || null })
        const member = await getMemberById(entry.discordId)
        if (!member) return res.json({ allowed: false, verifyUrl: VERIFY_URL || null })
        const memberRoles = Array.isArray(member.roles) ? member.roles : []
        const hasRequiredRole = memberRoles.some(r => requiredRoles.includes(r))
        return res.json({ allowed: hasRequiredRole, verifyUrl: VERIFY_URL || null })
    } catch (e) {
        return res.status(500).json({ allowed: false, verifyUrl: VERIFY_URL || null })
    }
})

app.listen(PORT || 3000, () => {
    console.log("Server running on port", PORT || 3000)
})
