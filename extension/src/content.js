const OVERLAY_ID = 'mailshield-overlay';

const urgencyPatterns = [
  /\burgent\b/i,
  /immediate action/i,
  /final notice/i,
  /act now/i,
  /account.*suspend/i,
  /즉시/i,
  /긴급/i,
  /마지막 경고/i,
];

const credentialPatterns = [
  /\bpassword\b/i,
  /credit card/i,
  /social security/i,
  /bank account/i,
  /비밀번호/i,
  /계좌번호/i,
  /개인정보/i,
];

const moneyPatterns = [
  /million/i,
  /wire transfer/i,
  /western union/i,
  /inheritance/i,
  /lottery/i,
  /송금/i,
];

const threatPatterns = [
  /legal action/i,
  /arrest/i,
  /lawsuit/i,
  /hacked/i,
  /blackmail/i,
  /협박/i,
  /해킹/i,
];

const linkLurePatterns = [
  /문서\s*확인/i,
  /확인\s*부탁/i,
  /외부\s*포털/i,
  /portal/i,
  /open/i,
  /click/i,
  /review/i,
  /access/i,
  /shared/i,
  /invoice/i,
  /document/i,
  /login/i,
  /sign in/i,
  /verify/i,
  /shared document/i,
  /please review/i,
];

const malwareLurePatterns = [
  /download/i,
  /install/i,
  /run/i,
  /enable macro/i,
  /update now/i,
  /patch/i,
  /viewer/i,
  /다운로드/i,
  /설치/i,
  /실행/i,
  /업데이트/i,
  /매크로/i,
];

const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click', '.zip'];

let lastSignature = '';
let analyzeTimer = null;
let settleTimer = null;
let debugVisible = false;
let analysisState = 'idle';
let lastSeenLocationKey = '';
let lastObservedSignature = '';
let isRunning = false;
let pendingRun = false;
let pollIntervalId = null;
let documentClickBound = false;
let overlayClickBound = false;

function detectProvider() {
  const host = location.hostname;
  if (host.includes('mail.google.com')) return 'gmail';
  if (host.includes('outlook.')) return 'outlook';
  return null;
}

function extractMailContext() {
  const provider = detectProvider();
  if (provider === 'gmail') return extractGmailContext();
  if (provider === 'outlook') return extractOutlookContext();
  return null;
}

function expandGmailThread() {
  const selectors = [
    'img[alt="Show trimmed content"]',
    'span[role="button"][data-tooltip*="Expand"]',
    'div[role="button"][aria-label*="Show trimmed content"]',
    'div[role="button"][aria-label*="더보기"]',
    'div[role="button"][aria-label*="전체 표시"]'
  ];

  for (const selector of selectors) {
    document.querySelectorAll(selector).forEach((el) => {
      try { el.click(); } catch {}
    });
  }
}

function extractGmailContext() {
  expandGmailThread();

  const subject = firstText(['h2.hP', 'h2[data-thread-perm-id]', 'div[role=main] h2']);
  const messageCards = Array.from(document.querySelectorAll('div[role="listitem"]')).filter((node) => node.querySelector('div.a3s'));
  const bodyNodes = messageCards.flatMap((card) => Array.from(card.querySelectorAll('div.a3s')));
  const allBodyText = bodyNodes.map((node) => collectText(node)).filter(Boolean);
  const fullText = dedupe(allBodyText).join('\n\n---\n\n');
  const bodySnippet = truncate(fullText, 1800);

  const primarySenderChip = document.querySelector('span.gD[email], h3.iw span[email], span[email][name]');
  const senderName = (primarySenderChip?.getAttribute('name') || primarySenderChip?.textContent || firstText(['span.gD', 'h3.iw span[email]'])).trim();
  const senderEmail = (primarySenderChip?.getAttribute('email') || primarySenderChip?.getAttribute('data-hovercard-id') || '').trim();
  const replyTo = inferReplyToGmail(fullText);

  const links = dedupeByKey(
    bodyNodes.flatMap((node) => Array.from(node.querySelectorAll('a[href]')).map((a) => ({
      text: (a.textContent || a.getAttribute('title') || a.href || '').trim(),
      href: a.href
    }))).filter((link) => link.href),
    (item) => `${item.text}|${item.href}`
  ).slice(0, 100);

  const attachments = dedupe(
    Array.from(document.querySelectorAll('div.aQH span.aZo, div.aQH div[download_url], div[download_url], span[data-tooltip*="attachment"]'))
      .map((el) => (el.textContent || '').trim())
      .filter(Boolean)
  ).slice(0, 30);

  if (!subject && !senderEmail && !fullText) return null;

  return {
    provider: 'gmail',
    mode: 'thread-dom-full',
    subject,
    senderName,
    senderEmail,
    replyTo,
    bodySnippet,
    fullText,
    links,
    attachments,
    sourceUrl: location.href,
    coverage: {
      messageCount: messageCards.length || 1,
      bodyBlockCount: bodyNodes.length,
      textLength: fullText.length,
      linkCount: links.length,
      attachmentCount: attachments.length
    }
  };
}

function inferReplyToGmail(fullText) {
  const text = `${document.body.innerText || ''}\n${fullText || ''}`;
  const match = text.match(/reply-to\s*:?\s*([A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,})/i);
  return match ? match[1] : '';
}

function extractOutlookContext() {
  const subject = firstText(['[role="heading"]', '[data-app-section="MailReadCompose"] h1']);
  const senderName = firstText(['[data-testid="message-sender-name"]', '[aria-label^="From"]']);
  const senderEmail = inferEmailFromText(senderName) || inferEmailFromText(document.body.innerText);
  const bodyNodes = Array.from(document.querySelectorAll('[data-testid="message-body"], [aria-label="Message body"]'));
  const fullText = dedupe(bodyNodes.map((node) => collectText(node)).filter(Boolean)).join('\n\n---\n\n');
  const bodySnippet = truncate(fullText, 1800);
  const links = dedupeByKey(
    bodyNodes.flatMap((node) => Array.from(node.querySelectorAll('a[href]')).map((a) => ({ text: (a.textContent || '').trim(), href: a.href }))),
    (item) => `${item.text}|${item.href}`
  ).slice(0, 100);
  const attachments = dedupe(Array.from(document.querySelectorAll('[data-testid="attachment-name"]')).map((el) => (el.textContent || '').trim()).filter(Boolean)).slice(0, 30);

  if (!subject && !senderName && !fullText) return null;

  return {
    provider: 'outlook',
    mode: 'thread-dom-full',
    subject,
    senderName,
    senderEmail,
    replyTo: '',
    bodySnippet,
    fullText,
    links,
    attachments,
    sourceUrl: location.href,
    coverage: {
      messageCount: bodyNodes.length || 1,
      bodyBlockCount: bodyNodes.length,
      textLength: fullText.length,
      linkCount: links.length,
      attachmentCount: attachments.length
    }
  };
}

function analyzeMailContext(context) {
  const sender = context.senderEmail || '';
  const replyTo = context.replyTo || '';
  const subject = context.subject || '';
  const body = context.fullText || context.bodySnippet || '';
  const urls = normalizeUrlsFromContext(context);
  const text = `${subject} ${body}`.toLowerCase();

  const senderDomain = extractDomain(sender);
  const replyDomain = extractDomain(replyTo);
  const senderRoot = rootDomain(senderDomain);
  const replyRoot = rootDomain(replyDomain);

  const urgencyScore = countPatternMatches(text, urgencyPatterns);
  const credentialRequest = countPatternMatches(text, credentialPatterns) > 0 ? 1 : 0;
  const moneyRequest = countPatternMatches(text, moneyPatterns) > 0 ? 1 : 0;
  const threatLanguage = countPatternMatches(text, threatPatterns) > 0 ? 1 : 0;
  const linkLureScore = countPatternMatches(text, linkLurePatterns);
  const malwareLureScore = countPatternMatches(text, malwareLurePatterns);

  const hasHttpUrl = urls.some((url) => url.toLowerCase().startsWith('http://')) ? 1 : 0;
  const hasSuspiciousUrl = urls.some((url) => suspiciousTlds.some((tld) => url.toLowerCase().includes(tld))) ? 1 : 0;
  const hasExternalUrl = urls.length > 0 ? 1 : 0;
  const suspiciousFileLink = urls.some((url) => /\.(exe|msi|js|vbs|scr|bat|cmd|ps1|iso|zip|rar)(\?|$|[\s/#])/i.test(url)) ? 1 : 0;
  const hasShortenedUrl = urls.some((url) => /(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|rebrand\.ly)/i.test(url)) ? 1 : 0;
  const longUrlPath = urls.some((url) => {
    try {
      const normalized = url.startsWith('http') ? url : `https://${url}`;
      const parsed = new URL(normalized);
      return (parsed.pathname || '').length >= 12;
    } catch {
      return false;
    }
  }) ? 1 : 0;
  const senderDomainMismatch = senderRoot && replyRoot && senderRoot !== replyRoot ? 1 : 0;

  let score = 0;
  score += urgencyScore * 1.5;
  score += credentialRequest * 2.5;
  score += moneyRequest * 2;
  score += threatLanguage * 2;
  score += hasHttpUrl * 1;
  score += hasSuspiciousUrl * 2;
  score += hasExternalUrl * 0.7;
  score += longUrlPath * 0.4;
  score += linkLureScore >= 2 ? 2.2 : linkLureScore === 1 ? 1.0 : 0;
  score += malwareLureScore >= 2 ? 2.6 : malwareLureScore === 1 ? 1.2 : 0;
  score += suspiciousFileLink * 3;
  score += hasShortenedUrl * 1;
  score += senderDomainMismatch * 0.8;

  const comboRisk = senderDomainMismatch && (credentialRequest || hasSuspiciousUrl || urgencyScore >= 2) ? 1 : 0;
  score += comboRisk * 1.7;

  const linkOnlyLure = hasExternalUrl && linkLureScore >= 2 && credentialRequest === 0 ? 1 : 0;
  score += linkOnlyLure * 1.8;

  const probability = Math.min(Math.round((score / 12) * 100), 99);
  const level = probability >= 75 ? 'high-risk' : probability >= 50 ? 'suspicious' : probability >= 25 ? 'caution' : 'safe';
  const reasons = [];

  if (senderDomainMismatch) reasons.push(`발신자 도메인(${senderRoot})과 Reply-To 도메인(${replyRoot})이 다릅니다.`);
  if (credentialRequest) reasons.push('비밀번호/개인정보 입력 요청 표현이 감지되었습니다.');
  if (hasSuspiciousUrl) reasons.push('수상한 TLD(.tk, .ml, .xyz 등) 링크가 감지되었습니다.');
  if (linkOnlyLure) reasons.push('직접 정보요구 없이 링크 클릭만 유도하는 피싱 패턴이 감지되었습니다.');
  if (suspiciousFileLink) reasons.push('실행파일/압축파일 다운로드 링크가 포함되어 있습니다 (악성코드 유포 가능성).');
  if (threatLanguage) reasons.push('협박 또는 공포 유도 문구가 포함되어 있습니다.');
  if (malwareLureScore) reasons.push('설치/실행/업데이트를 유도하는 표현이 감지되었습니다.');
  if (moneyRequest) reasons.push('금전 이체/보상 관련 표현이 포함되어 있습니다.');
  if (urgencyScore > 0) reasons.push('긴급 행동을 유도하는 표현이 보입니다.');
  if (hasHttpUrl) reasons.push('HTTPS가 아닌 HTTP 링크가 포함되어 있습니다.');
  if (hasExternalUrl && !hasSuspiciousUrl) reasons.push('외부 링크 포함 메일입니다. 실제 발신자/도메인 검증 후 접속하세요.');
  if (hasShortenedUrl) reasons.push('단축 URL이 포함되어 최종 접속 주소 확인이 필요합니다.');
  if ((context.coverage?.textLength || 0) < 200) reasons.push('수집된 본문 길이가 짧아 분석 신뢰도가 낮을 수 있습니다.');

  return { score: probability, level, reasons: dedupe(reasons).slice(0, 6), mode: 'rule-fallback' };
}

function normalizeUrlsFromContext(context) {
  const fromLinks = (context.links || []).map((link) => link?.href || '').filter(Boolean);
  if (fromLinks.length > 0) return fromLinks;
  return extractUrls(context.fullText || context.bodySnippet || '');
}

function scheduleAnalyze({ force = false, immediate = false } = {}) {
  clearTimeout(analyzeTimer);
  const delay = immediate ? 0 : 180;
  analyzeTimer = setTimeout(() => runAnalysis({ force }), delay);
}

function scheduleSettledAnalyze() {
  clearTimeout(settleTimer);
  settleTimer = setTimeout(() => runAnalysis({ force: true }), 900);
}

async function runAnalysis({ force = false } = {}) {
  if (isRunning) {
    pendingRun = true;
    return;
  }

  try {
    isRunning = true;
    setAnalysisState('running');

    const provider = detectProvider();
    if (!provider) {
      setAnalysisState('idle');
      return;
    }

    const context = extractMailContext();
    if (!context) {
      setAnalysisState('idle');
      scheduleAnalyze({ force: true, immediate: false });
      return;
    }

    const signature = JSON.stringify({
      url: context.sourceUrl,
      subject: context.subject,
      senderEmail: context.senderEmail,
      textLength: context.coverage?.textLength,
      linkCount: context.coverage?.linkCount,
      attachmentCount: context.coverage?.attachmentCount
    });

    if (!force && signature === lastSignature) {
      setAnalysisState('ready');
      return;
    }
    lastSignature = signature;

    const local = analyzeMailContext(context);

    let merged = local;
    try {
      const remote = await chrome.runtime.sendMessage({ type: 'analyzeMail', payload: context });
      merged = mergeResults(local, remote);
    } catch {
      merged = local;
    }

    renderOverlay(merged, context, { debug: debugVisible, state: analysisState });
    setAnalysisState('ready');
    console.debug('[MailShield]', { context, result: merged });
  } catch (error) {
    setAnalysisState('error');
    console.error('[MailShield] content error', error);
  } finally {
    isRunning = false;
    if (pendingRun) {
      pendingRun = false;
      scheduleAnalyze({ force: true, immediate: true });
    }
  }
}

function mergeResults(local, remote) {
  if (!remote) return local;
  return {
    score: Math.max(local.score, remote.score ?? 0),
    level: strongerLevel(local.level, remote.level),
    reasons: [...new Set([...(local.reasons || []), ...(remote.reasons || [])])].slice(0, 6),
    mode: remote.mode || local.mode,
    model: remote.model || undefined,
  };
}

function strongerLevel(a, b) {
  const order = ['safe', 'caution', 'suspicious', 'high-risk'];
  return order[Math.max(order.indexOf(a || 'safe'), order.indexOf(b || 'safe'))];
}

function renderOverlay(result, context, options = {}) {
  let root = document.getElementById(OVERLAY_ID);
  if (!root) {
    root = document.createElement('div');
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
          <div class="mailshield-title">MailShield Unified</div>
          <div class="mailshield-subtitle">${badge.label} · score ${result.score}</div>
        </div>
        <div class="mailshield-badge">${badge.emoji}</div>
      </div>
      <div class="mailshield-actions">
        <button class="mailshield-btn mailshield-btn-primary" data-action="start-analysis">분석 시작</button>
        <button class="mailshield-btn" data-action="toggle-debug">디버그 ${options.debug ? '숨기기' : '보기'}</button>
      </div>
      <div class="mailshield-status">${escapeHtml(formatState(options.state || analysisState))}${result.mode ? ` · ${result.mode}${result.model ? ` (${result.model})` : ''}` : ''}</div>
      <div class="mailshield-section"><strong>수집 범위</strong><br>${escapeHtml(formatCoverage(context.coverage, context.mode))}</div>
      <div class="mailshield-section"><strong>제목</strong><br>${escapeHtml(context.subject || '(없음)')}</div>
      <div class="mailshield-section"><strong>발신자</strong><br>${escapeHtml(formatSender(context))}</div>
      ${topLinks.length ? `<div class="mailshield-section"><strong>상위 링크</strong><br>${topLinks.map((l) => `<div class="mailshield-mini">${escapeHtml(shorten(l.text || l.href, 46))}</div>`).join('')}</div>` : ''}
      ${attachments.length ? `<div class="mailshield-section"><strong>첨부</strong><br>${attachments.map((name) => `<div class="mailshield-mini">${escapeHtml(name)}</div>`).join('')}</div>` : ''}
      <div class="mailshield-section"><strong>근거</strong>
        <ul>
          ${result.reasons.length ? result.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('') : '<li>즉시 의심되는 신호는 적습니다.</li>'}
        </ul>
      </div>
      ${options.debug ? renderDebug(context) : ''}
    </div>`;
}

function renderDebug(context) {
  return `<details class="mailshield-debug" open><summary>디버그 컨텍스트</summary><pre>${escapeHtml(JSON.stringify(context, null, 2))}</pre></details>`;
}

function hardRefreshAnalysis() {
  clearTimeout(analyzeTimer);
  clearTimeout(settleTimer);
  lastSignature = '';
  lastObservedSignature = '';
  lastSeenLocationKey = `${location.href}|${document.title}`;
  pendingRun = false;
  isRunning = false;
  setAnalysisState('running');
  scheduleAnalyze({ force: true, immediate: true });
  setTimeout(() => scheduleAnalyze({ force: true, immediate: true }), 250);
  setTimeout(() => scheduleAnalyze({ force: true, immediate: true }), 900);
}

function bindOverlayActions() {
  if (overlayClickBound) return;
  overlayClickBound = true;

  document.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const actionEl = target.closest(`#${OVERLAY_ID} [data-action]`);
    if (!actionEl) return;

    event.preventDefault();
    event.stopPropagation();

    const action = actionEl.getAttribute('data-action');
    if (action === 'start-analysis') {
      hardRefreshAnalysis();
      return;
    }

    if (action === 'toggle-debug') {
      debugVisible = !debugVisible;
      hardRefreshAnalysis();
    }
  }, true);
}

function setAnalysisState(state) {
  analysisState = state;
  const statusEl = document.querySelector('#mailshield-overlay .mailshield-status');
  if (statusEl) statusEl.textContent = formatState(state);
}

function formatState(state) {
  switch (state) {
    case 'running': return '분석 중…';
    case 'ready': return '자동 재분석 활성화';
    case 'error': return '분석 오류';
    default: return '대기 중';
  }
}

function formatCoverage(coverage = {}, mode = '') {
  const parts = [];
  if (mode) parts.push(mode);
  if (coverage.messageCount) parts.push(`메시지 ${coverage.messageCount}개`);
  if (coverage.textLength) parts.push(`본문 ${coverage.textLength}자`);
  if (coverage.linkCount || coverage.linkCount === 0) parts.push(`링크 ${coverage.linkCount}개`);
  if (coverage.attachmentCount || coverage.attachmentCount === 0) parts.push(`첨부 ${coverage.attachmentCount}개`);
  return parts.join(' · ') || '수집 정보 없음';
}

function formatSender(context) {
  const name = context.senderName || '';
  const email = context.senderEmail || '';
  const replyTo = context.replyTo ? ` / Reply-To: ${context.replyTo}` : '';
  if (name && email && !name.includes(email)) return `${name} <${email}>${replyTo}`;
  return `${name || email || '(확인 실패)'}${replyTo}`;
}

function badgeFor(level) {
  switch (level) {
    case 'high-risk': return { label: '고위험', emoji: '⛔' };
    case 'suspicious': return { label: '피싱 의심', emoji: '⚠️' };
    case 'caution': return { label: '주의', emoji: '👀' };
    default: return { label: '대체로 정상', emoji: '✅' };
  }
}

function countPatternMatches(text, patterns) {
  return patterns.reduce((acc, pattern) => (pattern.test(text) ? acc + 1 : acc), 0);
}

function extractDomain(input) {
  const raw = String(input || '').trim().replace(/^mailto:/i, '');
  const match = raw.match(/@([\w.-]+)/);
  if (match) return match[1].toLowerCase().replace(/[>),.;]+$/g, '');
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function rootDomain(domain) {
  if (!domain) return '';
  const parts = domain.split('.').filter(Boolean);
  if (parts.length <= 2) return domain;
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

function extractUrls(text) {
  const matches = String(text || '').match(/(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi);
  return matches || [];
}

function dedupe(list) {
  return [...new Set(list)];
}

function dedupeByKey(list, keyFn) {
  const seen = new Set();
  const result = [];
  for (const item of list) {
    const key = keyFn(item);
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

function firstText(selectors) {
  for (const selector of selectors) {
    const value = (document.querySelector(selector)?.textContent || '').trim();
    if (value) return value;
  }
  return '';
}

function collectText(node) {
  return (node?.innerText || node?.textContent || '').replace(/\s+/g, ' ').trim();
}

function inferEmailFromText(text) {
  const match = (text || '').match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i);
  return match ? match[0] : '';
}

function truncate(value, max) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function shorten(value, max) {
  return value.length > max ? `${value.slice(0, max)}…` : value;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function handlePossibleMailChange() {
  const nextKey = `${location.href}|${firstText(['h2.hP', 'h2[data-thread-perm-id]', 'div[role=main] h2'])}`;
  const quickContext = extractMailContext();
  const observedSignature = quickContext
    ? JSON.stringify({
        url: quickContext.sourceUrl,
        subject: quickContext.subject,
        senderEmail: quickContext.senderEmail,
        textLength: quickContext.coverage?.textLength,
        linkCount: quickContext.coverage?.linkCount,
        attachmentCount: quickContext.coverage?.attachmentCount
      })
    : '';

  if (nextKey !== lastSeenLocationKey || (observedSignature && observedSignature !== lastObservedSignature)) {
    lastSeenLocationKey = nextKey;
    lastObservedSignature = observedSignature;
    lastSignature = '';
    scheduleAnalyze({ force: true, immediate: true });
    return;
  }

  scheduleAnalyze({ force: false, immediate: false });
  scheduleSettledAnalyze();
}

const observer = new MutationObserver(() => handlePossibleMailChange());
observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true });
window.addEventListener('hashchange', () => {
  lastSignature = '';
  handlePossibleMailChange();
});
window.addEventListener('load', () => {
  lastSignature = '';
  handlePossibleMailChange();
});
window.addEventListener('popstate', () => {
  lastSignature = '';
  handlePossibleMailChange();
});

function bindDocumentNavigationHooks() {
  if (documentClickBound) return;
  documentClickBound = true;

  document.addEventListener('click', (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;

    const clickable = target.closest('tr[role="row"], [data-legacy-thread-id], a[href*="#inbox/"], a[href*="#all/"], a[href*="#label/"]');
    if (!clickable) return;

    setTimeout(() => hardRefreshAnalysis(), 60);
    setTimeout(() => hardRefreshAnalysis(), 350);
    setTimeout(() => hardRefreshAnalysis(), 1200);
  }, true);
}

function startPolling() {
  if (pollIntervalId) clearInterval(pollIntervalId);
  pollIntervalId = setInterval(() => {
    handlePossibleMailChange();
  }, 1200);
}

lastSeenLocationKey = `${location.href}|${document.title}`;
bindOverlayActions();
bindDocumentNavigationHooks();
startPolling();
scheduleAnalyze({ force: true, immediate: true });
