export function detectProvider() {
  const host = location.hostname;
  if (host.includes("mail.google.com")) return "gmail";
  if (host.includes("outlook.")) return "outlook";
  return null;
}

export function extractMailContext() {
  const provider = detectProvider();
  if (provider === "gmail") return extractGmailContext();
  if (provider === "outlook") return extractOutlookContext();
  return null;
}

function extractGmailContext() {
  const subject = firstText([
    "h2.hP",
    "h2[data-thread-perm-id]",
    "div[role=main] h2"
  ]);

  const senderChip = document.querySelector("span.gD[email], h3.iw span[email], span[email][name]");
  const senderName = (senderChip?.getAttribute("name") || senderChip?.textContent || firstText(["span.gD", "h3.iw span[email]"])).trim();
  const senderEmail = (senderChip?.getAttribute("email") || senderChip?.getAttribute("data-hovercard-id") || "").trim();

  const bodyRoot = document.querySelector("div.a3s.aiL ") || document.querySelector("div.a3s") || document.querySelector("div[role=listitem] div.a3s");
  const bodySnippet = collectText(bodyRoot);

  const links = Array.from((bodyRoot || document).querySelectorAll("a[href]"))
    .slice(0, 20)
    .map((a) => ({
      text: (a.textContent || a.getAttribute("title") || a.href || "").trim(),
      href: a.href
    }))
    .filter((link) => link.href);

  const attachments = Array.from(document.querySelectorAll("div.aQH span.aZo, div.aQH div[download_url], div[download_url]"))
    .slice(0, 10)
    .map((el) => (el.textContent || "").trim())
    .filter(Boolean);

  const replyTo = inferReplyToGmail();

  if (!subject && !senderEmail && !bodySnippet) return null;

  return {
    provider: "gmail",
    subject,
    senderName,
    senderEmail,
    replyTo,
    bodySnippet: truncate(bodySnippet, 1200),
    links,
    attachments,
    sourceUrl: location.href
  };
}

function inferReplyToGmail() {
  const fullText = document.body.innerText || "";
  const match = fullText.match(/reply-to\s*:?\s*([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i);
  return match ? match[1] : "";
}

function extractOutlookContext() {
  const subject = firstText(['[role="heading"]', '[data-app-section="MailReadCompose"] h1']);
  const senderName = firstText(['[data-testid="message-sender-name"]', '[aria-label^="From"]']);
  const senderEmail = inferEmailFromText(senderName) || inferEmailFromText(document.body.innerText);
  const bodyRoot = document.querySelector('[data-testid="message-body"]') || document.querySelector('[aria-label="Message body"]');
  const bodySnippet = collectText(bodyRoot);
  const links = Array.from((bodyRoot || document).querySelectorAll('a[href]'))
    .slice(0, 20)
    .map((a) => ({ text: (a.textContent || "").trim(), href: a.href }));
  const attachments = Array.from(document.querySelectorAll('[data-testid="attachment-name"]'))
    .slice(0, 10)
    .map((el) => (el.textContent || "").trim())
    .filter(Boolean);

  if (!subject && !senderName && !bodySnippet) return null;

  return {
    provider: "outlook",
    subject,
    senderName,
    senderEmail,
    replyTo: "",
    bodySnippet: truncate(bodySnippet, 1200),
    links,
    attachments,
    sourceUrl: location.href
  };
}

function firstText(selectors) {
  for (const selector of selectors) {
    const value = (document.querySelector(selector)?.textContent || "").trim();
    if (value) return value;
  }
  return "";
}

function collectText(node) {
  return (node?.innerText || node?.textContent || "").replace(/\s+/g, " ").trim();
}

function inferEmailFromText(text) {
  const match = (text || "").match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0] : "";
}

function truncate(value, max) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}
