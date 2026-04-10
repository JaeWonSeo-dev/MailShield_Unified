const OVERLAY_ID = "mailshield-overlay";

export function renderOverlay(result, context, options = {}) {
  let root = document.getElementById(OVERLAY_ID);
  if (!root) {
    root = document.createElement("div");
    root.id = OVERLAY_ID;
    document.documentElement.appendChild(root);
  }

  const badge = badgeFor(result.level);
  const topLinks = (context.links || []).slice(0, 3);
  const attachments = (context.attachments || []).slice(0, 3);

  root.innerHTML = `
    <div class="mailshield-card mailshield-${result.level}">
      <div class="mailshield-header">
        <div>
          <div class="mailshield-title">MailShield</div>
          <div class="mailshield-subtitle">${badge.label} · score ${result.score}</div>
        </div>
        <div class="mailshield-badge">${badge.emoji}</div>
      </div>

      <div class="mailshield-actions">
        <button class="mailshield-btn" data-action="reanalyze">다시 분석</button>
        <button class="mailshield-btn" data-action="toggle-debug">디버그 ${options.debug ? '숨기기' : '보기'}</button>
      </div>

      <div class="mailshield-section"><strong>제목</strong><br>${escapeHtml(context.subject || "(없음)")}</div>
      <div class="mailshield-section"><strong>발신자</strong><br>${escapeHtml(formatSender(context))}</div>
      ${topLinks.length ? `<div class="mailshield-section"><strong>링크</strong><br>${topLinks.map((l) => `<div class="mailshield-mini">${escapeHtml(shorten(l.text || l.href, 46))}</div>`).join("")}</div>` : ""}
      ${attachments.length ? `<div class="mailshield-section"><strong>첨부</strong><br>${attachments.map((name) => `<div class="mailshield-mini">${escapeHtml(name)}</div>`).join("")}</div>` : ""}
      <div class="mailshield-section"><strong>근거</strong>
        <ul>
          ${result.reasons.length ? result.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("") : "<li>즉시 의심되는 신호는 적습니다.</li>"}
        </ul>
      </div>
      ${options.debug ? renderDebug(context) : ""}
    </div>
  `;
}

function renderDebug(context) {
  return `
    <details class="mailshield-debug" open>
      <summary>디버그 컨텍스트</summary>
      <pre>${escapeHtml(JSON.stringify(context, null, 2))}</pre>
    </details>
  `;
}

function formatSender(context) {
  const name = context.senderName || "";
  const email = context.senderEmail || "";
  const replyTo = context.replyTo ? ` / Reply-To: ${context.replyTo}` : "";
  if (name && email && !name.includes(email)) return `${name} <${email}>${replyTo}`;
  return `${name || email || "(확인 실패)"}${replyTo}`;
}

function shorten(value, max) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function badgeFor(level) {
  switch (level) {
    case "high-risk": return { label: "고위험", emoji: "⛔" };
    case "suspicious": return { label: "피싱 의심", emoji: "⚠️" };
    case "caution": return { label: "주의", emoji: "👀" };
    default: return { label: "대체로 정상", emoji: "✅" };
  }
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
