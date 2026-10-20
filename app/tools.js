// Renders the "More local tools" links into any element with [data-tools]. Plain links only.
import { TOOLS } from '../src/brand.js';
document.querySelectorAll('[data-tools]').forEach((box) => {
  TOOLS.forEach((t) => {
    const a = document.createElement('a'); a.href = t.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = t.label + ' ↗';
    box.append(a);
  });
});
