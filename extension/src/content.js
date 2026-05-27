const analyzeMailContext = globalThis.MailShieldRiskEngine?.analyzeMailContext || (() => ({
  label: 0,
  verdict: 'legit',
  score: 0,
  level: 'safe',
  reasons: ['로컬 fallback 엔진을 불러오지 못했습니다.'],
  mode: 'rule-fallback'
}));

const OVERLAY_ID = 'mailshield-overlay';

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

  if (remote.mode === 'rule-fallback' || remote.mode === 'rule-api') {
    return {
      label: remote.label ?? local.label ?? 0,
      verdict: remote.verdict || local.verdict || 'legit',
      score: remote.score ?? local.score ?? 0,
      phishing_score: remote.phishing_score ?? local.phishing_score ?? remote.score ?? local.score ?? 0,
      spam_score: remote.spam_score ?? local.spam_score ?? 0,
      classification: remote.classification || local.classification || remote.verdict || local.verdict || 'legit',
      class_probabilities: remote.class_probabilities || local.class_probabilities || undefined,
      confidence: remote.confidence ?? local.confidence ?? ((remote.score ?? local.score ?? 0) / 100),
      level: strongerLevel(local.level, remote.level),
      reasons: [...new Set([...(remote.reasons || []), ...(local.reasons || [])])].slice(0, 6),
      mode: remote.mode,
      model: remote.model || undefined,
      rule_features: remote.rule_features || undefined,
    };
  }

  return {
    label: remote.label ?? local.label ?? 0,
    verdict: remote.verdict || local.verdict || 'legit',
    score: remote.score ?? local.score ?? 0,
    phishing_score: remote.phishing_score ?? local.phishing_score ?? remote.score ?? local.score ?? 0,
    spam_score: remote.spam_score ?? local.spam_score ?? 0,
    classification: remote.classification || local.classification || remote.verdict || local.verdict || 'legit',
    class_probabilities: remote.class_probabilities || local.class_probabilities || undefined,
    confidence: remote.confidence ?? local.confidence ?? ((remote.score ?? local.score ?? 0) / 100),
    level: remote.level || strongerLevel(local.level, remote.level),
    reasons: [...new Set([...(remote.reasons || []), ...(local.reasons || [])])].slice(0, 6),
    mode: remote.mode || local.mode,
    model: remote.model || undefined,
    rule_features: remote.rule_features || undefined,
  };
}

function strongerLevel(a, b) {
  const order = ['safe', 'spam', 'phishing-low', 'caution', 'phishing-medium', 'suspicious', 'phishing-high', 'high-risk'];
  return order[Math.max(order.indexOf(a || 'safe'), order.indexOf(b || 'safe'))];
}

function renderOverlay(result, context, options = {}) {
  let root = document.getElementById(OVERLAY_ID);
  if (!root) {
    root = document.createElement('div');
    root.id = OVERLAY_ID;
    document.documentElement.appendChild(root);
  }

  const normalized = normalizeResult(result);
  const badge = badgeFor(normalized.level, normalized.verdict);
  const topLinks = (context.links || []).slice(0, 3);
  const attachments = (context.attachments || []).slice(0, 3);
  const confidence = Math.round((normalized.confidence ?? (normalized.score || 0) / 100) * 100);
  const scoreLine = formatScoreLine(normalized);

  root.innerHTML = `
    <div class="mailshield-card mailshield-${normalized.level}">
      <div class="mailshield-header">
        <div>
          <div class="mailshield-title">PhishingMail Detection</div>
          <div class="mailshield-subtitle">${badge.label} · ${scoreLine} · confidence ${confidence}%</div>
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
          ${normalized.reasons.length ? normalized.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join('') : '<li>즉시 의심되는 피싱 신호는 적습니다.</li>'}
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

function normalizeResult(result = {}) {
  const verdict = result.classification || result.verdict || (result.label === 2 ? 'phishing' : result.label === 1 ? 'spam' : 'legit');
  let level = result.level || 'safe';
  if (level === 'high-risk') level = 'phishing-high';
  if (level === 'suspicious') level = 'phishing-medium';
  if (level === 'caution' && verdict === 'phishing') level = 'phishing-low';
  if (verdict === 'spam') level = 'spam';
  if (verdict === 'legit' || verdict === 'ham') level = 'safe';
  return {
    ...result,
    verdict: verdict === 'ham' ? 'legit' : verdict,
    level,
    phishing_score: result.phishing_score ?? result.score ?? 0,
    spam_score: result.spam_score ?? 0,
    reasons: result.reasons || [],
  };
}

function formatScoreLine(result) {
  if (result.verdict === 'phishing') {
    return `피싱 메일 · 피싱 점수 ${result.phishing_score}`;
  }
  if (result.verdict === 'spam') {
    return `스팸 메일 · 스팸 점수 ${result.spam_score} · 피싱 점수 ${result.phishing_score}`;
  }
  return `정상 메일 · 피싱 점수 ${result.phishing_score}`;
}

function badgeFor(level, verdict) {
  if (verdict === 'spam' || level === 'spam') return { label: '스팸', emoji: 'AD' };
  switch (level) {
    case 'phishing-high':
    case 'high-risk': return { label: '피싱 강도 높음', emoji: '!!' };
    case 'phishing-medium':
    case 'suspicious': return { label: '피싱 강도 중간', emoji: '!' };
    case 'phishing-low':
    case 'caution': return { label: '피싱 강도 낮음', emoji: '?' };
    default: return { label: '정상', emoji: 'OK' };
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
