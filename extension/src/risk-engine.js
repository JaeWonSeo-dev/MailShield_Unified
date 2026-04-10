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

const suspiciousTlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click", ".zip"];

export function analyzeMailContext(context) {
  const sender = context.senderEmail || "";
  const replyTo = context.replyTo || "";
  const subject = context.subject || "";
  const body = context.fullText || context.bodySnippet || "";
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

  const hasHttpUrl = urls.some((url) => url.toLowerCase().startsWith("http://")) ? 1 : 0;
  const hasSuspiciousUrl = urls.some((url) => suspiciousTlds.some((tld) => url.toLowerCase().includes(tld))) ? 1 : 0;
  const hasExternalUrl = urls.length > 0 ? 1 : 0;
  const suspiciousFileLink = urls.some((url) => /\.(exe|msi|js|vbs|scr|bat|cmd|ps1|iso|zip|rar)(\?|$|[\s/#])/i.test(url)) ? 1 : 0;
  const hasShortenedUrl = urls.some((url) => /(bit\.ly|tinyurl\.com|t\.co|rb\.gy|cutt\.ly|rebrand\.ly)/i.test(url)) ? 1 : 0;
  const longUrlPath = urls.some((url) => {
    try {
      const normalized = url.startsWith("http") ? url : `https://${url}`;
      const parsed = new URL(normalized);
      return (parsed.pathname || "").length >= 12;
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
  const level = probability >= 75 ? "high-risk" : probability >= 50 ? "suspicious" : probability >= 25 ? "caution" : "safe";

  const reasons = [];
  if (senderDomainMismatch) {
    reasons.push(`발신자 도메인(${senderRoot})과 Reply-To 도메인(${replyRoot})이 다릅니다.`);
  }
  if (credentialRequest) {
    reasons.push("비밀번호/개인정보 입력 요청 표현이 감지되었습니다.");
  }
  if (hasSuspiciousUrl) {
    reasons.push("수상한 TLD(.tk, .ml, .xyz 등) 링크가 감지되었습니다.");
  }
  if (linkOnlyLure) {
    reasons.push("직접 정보요구 없이 링크 클릭만 유도하는 피싱 패턴이 감지되었습니다.");
  }
  if (suspiciousFileLink) {
    reasons.push("실행파일/압축파일 다운로드 링크가 포함되어 있습니다 (악성코드 유포 가능성).");
  }
  if (threatLanguage) {
    reasons.push("협박 또는 공포 유도 문구가 포함되어 있습니다.");
  }
  if (malwareLureScore) {
    reasons.push("설치/실행/업데이트를 유도하는 표현이 감지되었습니다.");
  }
  if (moneyRequest) {
    reasons.push("금전 이체/보상 관련 표현이 포함되어 있습니다.");
  }
  if (urgencyScore > 0) {
    reasons.push("긴급 행동을 유도하는 표현이 보입니다.");
  }
  if (hasHttpUrl) {
    reasons.push("HTTPS가 아닌 HTTP 링크가 포함되어 있습니다.");
  }
  if (hasExternalUrl && !hasSuspiciousUrl) {
    reasons.push("외부 링크 포함 메일입니다. 실제 발신자/도메인 검증 후 접속하세요.");
  }
  if (hasShortenedUrl) {
    reasons.push("단축 URL이 포함되어 최종 접속 주소 확인이 필요합니다.");
  }

  return { score: probability, level, reasons: dedupe(reasons).slice(0, 6) };
}

function normalizeUrlsFromContext(context) {
  const fromLinks = (context.links || []).map((link) => link?.href || "").filter(Boolean);
  if (fromLinks.length > 0) return fromLinks;
  return extractUrls(context.fullText || context.bodySnippet || "");
}

function extractDomain(address) {
  const raw = String(address || "").trim().replace(/^mailto:/i, "");
  const match = raw.match(/@([\w.-]+)/);
  if (match) return match[1].toLowerCase().replace(/[>),.;]+$/g, "");
  try {
    return new URL(raw).hostname.toLowerCase();
  } catch {
    return "";
  }
}

function rootDomain(domain) {
  if (!domain) return "";
  const parts = domain.split(".").filter(Boolean);
  if (parts.length <= 2) return domain;
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

function extractUrls(text) {
  const matches = String(text || "").match(/(https?:\/\/[^\s<>"']+|www\.[^\s<>"']+)/gi);
  return matches || [];
}

function countPatternMatches(text, patterns) {
  return patterns.reduce((acc, pattern) => (pattern.test(text) ? acc + 1 : acc), 0);
}

function dedupe(list) {
  return [...new Set(list)];
}
