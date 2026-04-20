import { analyzeMailContext } from './risk-engine.js';

const DEFAULT_ML_API_URL = 'http://127.0.0.1:8765/analyze';

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === 'analyzeMail') {
    const context = message.payload || {};

    analyzeWithFallback(context)
      .then((result) => sendResponse(result))
      .catch((error) => {
        sendResponse({
          ...analyzeMailContext(context),
          mode: 'rule-fallback',
          apiError: String(error?.message || error),
        });
      });

    return true;
  }

  if (message?.type === 'getApiUrl') {
    getApiUrl().then((url) => sendResponse({ url }));
    return true;
  }
});

async function analyzeWithFallback(context) {
  try {
    const remote = await analyzeViaMlApi(context);
    return {
      ...remote,
      mode: remote.mode || 'ml-api',
    };
  } catch (error) {
    return {
      ...analyzeMailContext(context),
      mode: 'rule-fallback',
      apiError: String(error?.message || error),
    };
  }
}

async function getApiUrl() {
  const data = await chrome.storage.local.get(['mailshieldApiUrl']);
  return data.mailshieldApiUrl || DEFAULT_ML_API_URL;
}

async function analyzeViaMlApi(context) {
  const apiUrl = await getApiUrl();
  const response = await fetch(apiUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      provider: context.provider || '',
      sender: context.senderEmail || '',
      sender_name: context.senderName || '',
      reply_to: context.replyTo || '',
      subject: context.subject || '',
      body: context.fullText || context.bodySnippet || '',
      body_snippet: context.bodySnippet || '',
      links: (context.links || []).map((link) => ({
        href: link?.href || '',
        text: link?.text || '',
      })).filter((link) => link.href),
      attachments: context.attachments || [],
      source_url: context.sourceUrl || '',
      coverage: context.coverage || {},
    }),
  });

  if (!response.ok) {
    throw new Error(`ML API error: ${response.status}`);
  }

  return response.json();
}
