(function () {
  var EXPIRES_AT = Date.parse('2026-08-23T15:00:00-07:00');
  var STORAGE_KEY = 'af-event-popup-aug23';
  var IMG_SRC = '/images/breathwork-vocal-freedom-aug23.jpg';
  var EVENT_URL = '/offerings#august-23-event';

  if (Date.now() > EXPIRES_AT) return;
  try {
    if (sessionStorage.getItem(STORAGE_KEY) === '1') return;
  } catch (e) {}

  var style = document.createElement('style');
  style.textContent = [
    'body.af-event-popup-open { overflow: hidden; }',
    '#af-event-popup {',
    '  position: fixed; inset: 0; z-index: 200;',
    '  display: flex; align-items: center; justify-content: center;',
    '  padding: 1.25rem;',
    '  opacity: 0; pointer-events: none;',
    '  transition: opacity 0.35s ease;',
    '}',
    '#af-event-popup.open { opacity: 1; pointer-events: auto; }',
    '#af-event-popup .af-event-popup-scrim {',
    '  position: absolute; inset: 0;',
    '  background: rgba(10, 8, 6, 0.78);',
    '  backdrop-filter: blur(14px);',
    '  -webkit-backdrop-filter: blur(14px);',
    '}',
    '#af-event-popup .af-event-popup-dialog {',
    '  position: relative; z-index: 1;',
    '  width: min(520px, 92vw);',
    '  max-height: 90vh;',
    '  overflow: auto;',
    '  border-radius: 6px;',
    '  background: #f3ede0;',
    '  box-shadow: 0 40px 80px -20px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(28, 25, 23, 0.08);',
    '  transform: translateY(18px);',
    '  transition: transform 0.45s cubic-bezier(.2,.7,.2,1);',
    '}',
    '#af-event-popup.open .af-event-popup-dialog { transform: translateY(0); }',
    '#af-event-popup .af-event-popup-dialog img {',
    '  display: block; width: 100%; height: auto;',
    '}',
    '#af-event-popup .af-event-popup-details {',
    '  display: flex; align-items: center; justify-content: center;',
    '  min-height: 54px; padding: 0.9rem 1.25rem;',
    '  background: #f3ede0; color: #0e2a4f;',
    '  font-family: Inter, sans-serif; font-size: 12px; font-weight: 600;',
    '  letter-spacing: 0.2em; text-align: center; text-decoration: none;',
    '  text-transform: uppercase; transition: background 0.2s ease;',
    '}',
    '#af-event-popup .af-event-popup-details:hover { background: #fbf8f0; }',
    '#af-event-popup .af-event-popup-close {',
    '  position: absolute; top: 14px; right: 14px; z-index: 2;',
    '  width: 36px; height: 36px; border-radius: 999px;',
    '  background: rgba(10, 8, 6, 0.55);',
    '  border: 1px solid rgba(255, 255, 255, 0.22);',
    '  color: #fbf8f0;',
    '  cursor: pointer;',
    '  display: flex; align-items: center; justify-content: center;',
    '  font-size: 18px; line-height: 1;',
    '  transition: background 0.2s ease, transform 0.2s ease;',
    '}',
    '#af-event-popup .af-event-popup-close:hover {',
    '  background: rgba(10, 8, 6, 0.85);',
    '  transform: scale(1.05);',
    '}',
    '@media (prefers-reduced-motion: reduce) {',
    '  #af-event-popup, #af-event-popup .af-event-popup-dialog {',
    '    transition: none;',
    '  }',
    '}'
  ].join('');
  document.head.appendChild(style);

  var root = document.createElement('div');
  root.id = 'af-event-popup';
  root.setAttribute('role', 'dialog');
  root.setAttribute('aria-modal', 'true');
  root.setAttribute('aria-label', 'Upcoming event: Breathwork and Vocal Freedom at 108');
  root.innerHTML =
    '<div class="af-event-popup-scrim" data-close></div>' +
    '<div class="af-event-popup-dialog" role="document">' +
      '<button type="button" class="af-event-popup-close" aria-label="Close" data-close>&times;</button>' +
      '<img src="' + IMG_SRC + '" alt="Ancient Fire Breathwork and Vocal Freedom at 108. Sunday August 23, 12 to 3pm at 108 Walker\'s Hook Road, Salt Spring Island. Outdoor ceremony, weather pending, sliding scale $40 to $60. Breathwork with Ancient Fire and vocal freedom with Blair Francis. Bring a water bottle, comfortable clothing, and a yoga mat or pillow. Cash or e-transfer to Ancientfire@startmail.com. All are welcome." />' +
      '<a class="af-event-popup-details" href="' + EVENT_URL + '">View event details &rarr;</a>' +
    '</div>';

  var closeBtn = root.querySelector('.af-event-popup-close');
  var detailsLink = root.querySelector('.af-event-popup-details');
  var opened = false;
  var previousFocus = null;

  function rememberDismissed() {
    try { sessionStorage.setItem(STORAGE_KEY, '1'); } catch (e) {}
  }

  function close() {
    if (!opened) return;
    opened = false;
    root.classList.remove('open');
    document.body.classList.remove('af-event-popup-open');
    rememberDismissed();
    setTimeout(function () {
      if (root.parentNode) root.parentNode.removeChild(root);
    }, 350);
    if (previousFocus && typeof previousFocus.focus === 'function') previousFocus.focus();
  }

  function open() {
    if (opened) return;
    opened = true;
    previousFocus = document.activeElement;
    document.body.appendChild(root);
    document.body.classList.add('af-event-popup-open');
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        root.classList.add('open');
        if (closeBtn) closeBtn.focus();
      });
    });
  }

  root.addEventListener('click', function (e) {
    if (e.target && e.target.getAttribute('data-close') !== null) close();
  });

  if (detailsLink) detailsLink.addEventListener('click', rememberDismissed);

  document.addEventListener('keydown', function (e) {
    if (!opened) return;
    if (e.key === 'Escape') close();
    if (e.key === 'Tab') {
      if (e.shiftKey && document.activeElement === closeBtn) {
        e.preventDefault();
        detailsLink.focus();
      } else if (!e.shiftKey && document.activeElement === detailsLink) {
        e.preventDefault();
        closeBtn.focus();
      }
    }
  });

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(open, 500);
    });
  } else {
    setTimeout(open, 500);
  }
})();
