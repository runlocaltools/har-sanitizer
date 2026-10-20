// One place for outbound links. They are plain links: no query strings, no analytics, no scripts.
export const SITE = 'https://runlocaltools.online';
export const HAR_VIEWER_URL = SITE + '/har-viewer/';
export const HAR_SANITIZER_WEB_URL = SITE + '/har-sanitizer/';
export const STORE_URL = '';  // Chrome Web Store listing URL (fill in after publishing)
export const SOURCE_URL = 'https://github.com/runlocaltools/har-sanitizer'; // public source / repo URL, shown on the Prove-it-local page when set
export const TOOLS = [
  { label: 'HAR Sanitizer (web version)', url: HAR_SANITIZER_WEB_URL },
  { label: 'HAR Viewer', url: HAR_VIEWER_URL },
  { label: 'All local tools', url: SITE }
];
