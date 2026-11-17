// ShieldOTP On-Demand In-Page Floating Overlay Controller
// Zero RAM overhead on background tabs: injects overlay only into the active tab when clicked,
// then toggles visibility in 0ms on subsequent clicks.

chrome.action.onClicked.addListener(async (tab) => {
  if (!tab || !tab.id || !tab.url || /^(chrome|edge|about|chrome-extension):/i.test(tab.url)) {
    // Fallback for restricted browser pages (e.g. chrome://extensions) where Chrome blocks page scripts
    chrome.windows.create({
      url: chrome.runtime.getURL('popup.html'),
      type: 'popup',
      width: 360,
      height: 460,
      focused: true
    });
    return;
  }

  try {
    await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: toggleShieldOtpOverlay,
      args: [chrome.runtime.getURL('popup.html')]
    });
  } catch (err) {
    chrome.windows.create({
      url: chrome.runtime.getURL('popup.html'),
      type: 'popup',
      width: 360,
      height: 460,
      focused: true
    });
  }
});

function toggleShieldOtpOverlay(iframeUrl) {
  const HOST_ID = 'shieldotp-floating-overlay-host';
  let host = document.getElementById(HOST_ID);

  if (host) {
    const isHidden = host.style.display === 'none';
    host.style.display = isHidden ? 'block' : 'none';
    if (isHidden) {
      const shadow = host.shadowRoot;
      const iframe = shadow && shadow.querySelector('iframe');
      if (iframe && iframe.contentWindow) {
        iframe.contentWindow.postMessage({ type: 'SHIELDOTP_OVERLAY_SHOWN' }, '*');
      }
    }
    return;
  }

  // First click on this tab: create isolated Shadow DOM floating container (0ms toggle thereafter)
  host = document.createElement('div');
  host.id = HOST_ID;
  host.style.cssText = 'position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;display:block;';
  const shadow = host.attachShadow({ mode: 'open' });

  const style = document.createElement('style');
  style.textContent = `
    .backdrop {
      position: fixed;
      inset: 0;
      background: transparent;
      z-index: 2147483646;
    }
    .floating-card {
      position: fixed;
      top: 12px;
      right: 16px;
      width: 340px;
      height: 210px;
      max-height: 85vh;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 14px 38px rgba(0, 0, 0, 0.45), 0 0 0 1px rgba(154, 160, 166, 0.22);
      z-index: 2147483647;
      background: #131314;
      transition: height 0.14s ease, opacity 0.12s ease;
    }
    iframe {
      width: 100%;
      height: 100%;
      border: none;
      display: block;
      background: transparent;
    }
  `;

  const backdrop = document.createElement('div');
  backdrop.className = 'backdrop';
  backdrop.addEventListener('click', () => {
    host.style.display = 'none';
  });

  const card = document.createElement('div');
  card.className = 'floating-card';

  const iframe = document.createElement('iframe');
  iframe.src = iframeUrl;
  iframe.allow = 'clipboard-write; publickey-credentials-get; publickey-credentials-create';

  card.appendChild(iframe);
  shadow.appendChild(style);
  shadow.appendChild(backdrop);
  shadow.appendChild(card);
  document.documentElement.appendChild(host);

  window.addEventListener('message', (e) => {
    if (!e.data) return;
    if (e.data.type === 'SHIELDOTP_RESIZE' && typeof e.data.height === 'number') {
      const clamped = Math.min(Math.max(e.data.height, 115), 540);
      card.style.height = clamped + 'px';
    } else if (e.data.type === 'SHIELDOTP_CLOSE_OVERLAY') {
      host.style.display = 'none';
    }
  });

  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && host.style.display !== 'none') {
      host.style.display = 'none';
    }
  });
}
