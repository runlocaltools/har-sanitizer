// Opens the sanitizer in a full tab; shows the welcome page once after install. No host permissions, no network.
const APP = chrome.runtime.getURL('app/app.html');
chrome.runtime.onInstalled.addListener((d) => { if (d.reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('app/welcome.html') }); });
chrome.action.onClicked.addListener(async () => {
  const tabs = await chrome.tabs.query({ url: APP });
  if (tabs.length) { await chrome.tabs.update(tabs[0].id, { active: true }); await chrome.windows.update(tabs[0].windowId, { focused: true }); }
  else await chrome.tabs.create({ url: APP });
});
